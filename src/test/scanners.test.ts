import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanShellInjection, scanNetHttpInLoop, scanGemfileGroups } from '../scanners';

test('scanShellInjection flags system() with interpolation', () => {
  const hits = scanShellInjection('system("ping #{host}")');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, 'shell-injection');
});

test('scanShellInjection flags backtick interpolation', () => {
  const hits = scanShellInjection('result = `ls #{dir}`');
  assert.equal(hits.length, 1);
});

test('scanShellInjection flags %x[] interpolation', () => {
  const hits = scanShellInjection('out = %x[cat #{file}]');
  assert.equal(hits.length, 1);
});

test('scanShellInjection does not flag a static command', () => {
  const hits = scanShellInjection('system("uptime")');
  assert.equal(hits.length, 0);
});

test('scanShellInjection ignores commented-out lines', () => {
  const hits = scanShellInjection('# system("ping #{host}")');
  assert.equal(hits.length, 0);
});

test('scanNetHttpInLoop flags Net::HTTP.get inside an each-do loop', () => {
  const text = ['hosts.each do |host|', '  Net::HTTP.get(host, "/")', 'end'].join('\n');
  const hits = scanNetHttpInLoop(text);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, 'nethttp-per-iteration');
  assert.equal(hits[0].line, 2);
});

test('scanNetHttpInLoop flags Net::HTTP.post inside a while loop', () => {
  const text = ['while more_items?', '  Net::HTTP.post(url, body)', 'end'].join('\n');
  const hits = scanNetHttpInLoop(text);
  assert.equal(hits.length, 1);
});

test('scanNetHttpInLoop flags Net::HTTP inside a brace-block loop', () => {
  const text = ['hosts.each { |host|', '  Net::HTTP.get(host, "/")', '}'].join('\n');
  const hits = scanNetHttpInLoop(text);
  assert.equal(hits.length, 1);
});

test('scanNetHttpInLoop does not flag a call outside any loop', () => {
  const text = 'Net::HTTP.get(host, "/")';
  const hits = scanNetHttpInLoop(text);
  assert.equal(hits.length, 0);
});

test('scanNetHttpInLoop does not flag Net::HTTP.start (the reused-connection form)', () => {
  const text = ['hosts.each do |host|', '  Net::HTTP.start(host) { |http| http.get("/") }', 'end'].join('\n');
  const hits = scanNetHttpInLoop(text);
  assert.equal(hits.length, 0);
});

test('scanGemfileGroups flags an ungrouped dev/test gem', () => {
  const text = ['source "https://rubygems.org"', 'gem "rails"', 'gem "rspec"'].join('\n');
  const hits = scanGemfileGroups(text);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, 'ungrouped-dev-test-gem');
  assert.match(hits[0].message, /rspec/);
});

test('scanGemfileGroups does not flag a gem inside group :development, :test do', () => {
  const text = [
    'gem "rails"',
    'group :development, :test do',
    '  gem "rspec"',
    '  gem "pry"',
    'end',
  ].join('\n');
  const hits = scanGemfileGroups(text);
  assert.equal(hits.length, 0);
});

test('scanGemfileGroups does not flag a non-dev/test gem at the top level', () => {
  const text = 'gem "rails"';
  const hits = scanGemfileGroups(text);
  assert.equal(hits.length, 0);
});

test('scanGemfileGroups flags a gem correctly after a group block has closed', () => {
  const text = [
    'group :test do',
    '  gem "capybara"',
    'end',
    'gem "byebug"',
  ].join('\n');
  const hits = scanGemfileGroups(text);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].line, 4);
});
