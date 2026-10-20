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

release_path, _, release_triggers = workflow("release")
assert(release_triggers.key?("workflow_dispatch"), "#{release_path} must support manual releases")
release_push = release_triggers.fetch("push", {})
assert(release_push.key?("tags"), "#{release_path} must publish from version tags")
assert(!release_push.key?("branches"), "#{release_path} must not publish from branch pushes")

puts "Workflow policy verified: PR validation, scheduled security, explicit releases"
