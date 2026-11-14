#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

WORKFLOWS = File.expand_path("../workflows", __dir__)

def workflow(name)
  path = File.join(WORKFLOWS, "#{name}.yml")
  document = YAML.safe_load(File.read(path), aliases: true)
  triggers = document.key?("on") ? document.fetch("on") : document.fetch(true)
  [path, document, triggers]
end

def assert(condition, message)
  abort "workflow policy violation: #{message}" unless condition
end

def private_pull_request_runners(document)
  document.fetch("jobs").sum do |_name, job|
    condition = job.fetch("if", "").to_s
    next 0 if condition.include?("repository_visibility == 'public'")

    matrix = job.dig("strategy", "matrix", "include")
    matrix.is_a?(Array) ? matrix.length : 1
  end
end

%w[build test security].each do |name|
  path, document, triggers = workflow(name)
  assert(triggers.key?("pull_request"), "#{path} must validate pull requests")
  assert(!triggers.key?("push"), "#{path} must not repeat validation after merge")

  pull_request = triggers.fetch("pull_request") || {}
  assert(pull_request.key?("paths") || pull_request.key?("paths-ignore"),
         "#{path} must avoid irrelevant pull-request runs")

  concurrency = document.fetch("concurrency", {})
  assert(concurrency["cancel-in-progress"] == true,
         "#{path} must cancel superseded validation runs")
end

security_path, security, security_triggers = workflow("security")
assert(security_triggers.key?("schedule"), "security.yml must retain a scheduled scan")
private_scheduled_jobs = security.fetch("jobs").reject do |_name, job|
  condition = job.fetch("if", "").to_s
  condition.include?("repository_visibility == 'public'") ||
    condition.include?("event_name == 'pull_request'")
end
assert(private_scheduled_jobs.length == 1,
       "#{security_path} must use one billable private-repo job per scheduled scan")

pr_runner_count = %w[build test security].sum do |name|
  _, document, = workflow(name)
  private_pull_request_runners(document)
end
assert(pr_runner_count <= 3,
       "pull-request validation must use at most 3 private runner jobs, got #{pr_runner_count}")

release_path, release, release_triggers = workflow("release")
assert(release_triggers.key?("workflow_dispatch"), "#{release_path} must support manual releases")
release_push = release_triggers.fetch("push", {})
assert(release_push.key?("tags"), "#{release_path} must publish from version tags")
assert(!release_push.key?("branches"), "#{release_path} must not publish from branch pushes")

release_jobs = release.fetch("jobs")
publish = release_jobs.fetch("release")
assert(Array(publish["needs"]).include?("validate"),
       "release publication must depend on executable validation")
assert(release.fetch("permissions", {}) == {"contents" => "read"},
       "release workflow must default to read-only permissions")
assert(publish.dig("permissions", "id-token") == "write",
       "only the publishing job must request Google WIF OIDC")
validation_runs = release_jobs.fetch("validate").fetch("steps").map { |step| step.fetch("run", "") }.join("\n")
assert(validation_runs.include?("go test -race ./...") && validation_runs.include?("govulncheck ./..."),
       "release validation must run race tests and vulnerability checks")
publish_steps = publish.fetch("steps")
scan_index = publish_steps.index { |step| step.fetch("uses", "").include?("aquasecurity/trivy-action@") }
auth_index = publish_steps.index { |step| step.fetch("uses", "").include?("google-github-actions/auth@") }
push_index = publish_steps.index { |step| step.fetch("run", "").include?("docker push") }
assert(scan_index && auth_index && push_index && scan_index < auth_index && auth_index < push_index,
       "each published image must pass scanning before cloud authentication and push")
build = publish_steps.find { |step| step.fetch("uses", "").include?("docker/build-push-action@") }
assert(build && build.dig("with", "push") == false && build.dig("with", "load") == true,
       "release must build a local image without publishing before scanning")
scan = publish_steps.fetch(scan_index)
published_image = publish_steps.fetch(push_index).dig("env", "IMAGE")
assert(scan.dig("with", "image-ref") == published_image &&
       build.dig("with", "tags").lines.map(&:strip).include?(published_image),
       "the scanned local image must be the exact image pushed")
assert(scan.dig("with", "exit-code") == "1" && !scan["continue-on-error"],
       "release image scanning must fail closed")
assert(publish.fetch("if", "").include?("github.ref == 'refs/heads/main'") &&
       !publish.key?("environment"), "publishing OIDC subject must remain main-only")
source_checkout = publish_steps.find { |step| step.fetch("uses", "").include?("actions/checkout@") }
assert(source_checkout.dig("with", "ref") == "${{ needs.prepare.outputs.source_sha }}",
       "publishing must build the validated tag commit, even when main advances")
request = release_jobs.fetch("request-release")
assert(!request.fetch("permissions").key?("id-token") && !request.to_s.include?("secrets."),
       "tag dispatch must not receive cloud OIDC or production secrets")
assert(request.fetch("steps").any? { |step| step.fetch("run", "").include?("--ref main") },
       "tag dispatch must run the trusted main workflow")

release_jobs.each do |name, job|
  next if name == "release"

  assert(!job.fetch("permissions", {}).key?("id-token"),
         "only the publishing job may request OIDC")
end
notification = release_jobs.fetch("notify-failure")
assert(Array(notification["needs"]).sort == %w[prepare release validate] &&
       notification.fetch("if").include?("needs.validate.result == 'failure'") &&
       notification.fetch("if").include?("needs.release.result == 'failure'"),
       "Slack must still receive validation and publication failures")
assert(release.dig("concurrency", "cancel-in-progress") == false,
       "publishing runs must be serialized without cancellation")

puts "Workflow policy verified: PR validation, scheduled security, explicit releases"
