#!/usr/bin/env ruby

require 'rubygems'
require 'fileutils'
require 'socket'
require 'grit'
require 'ruby_gpg'
require 'securerandom'

module RubyGpg
  def gpg_command
    "#{config.executable} --homedir #{config.homedir} --quiet --yes"
  end
end

# This implementation leaks:
# - names of passwords
# - number of passwords stored per service
# - approximate size of passwords
# - timestamps

module VaultBox
  class Config
    Default = {
      :dir => '~/Dropbox/vaultbox',
      :key => '5989B94E'
    }

    def self.get(k); Default.fetch(k); end
    def self.dir; File.expand_path(get(:dir)); end
    def self.hostname; Socket.gethostname; end
    def self.key; get(:key); end
  end

  module FS
    class FSError < StandardError; end

    extend self

    def dir; Config.dir; end

    def ls(dir)
      Dir.entries(dir).reject{|e| e =~ /^\./}
    end

    def passwords
      ls(self.dir)
    end

    def init
      FileUtils.mkdir_p(dir)
      Grit::Repo.init(dir)
    end

    def gitpath
      File.join(dir, '.git')
    end

    def repo
      @repo ||= Grit::Repo.new(dir)
    end

    def commit(*f)
      Dir.chdir(dir) do
        self.repo.add(*f)
        t = Time.now.utc.iso8601
        h = Config.hostname
        self.repo.commit_all("Automated commit at #{t} on #{h}")
      end
    end

    def latest(name)
      d = File.join(dir, name)
      if File.directory?(d)
        if last = ls(d).sort.last
          File.join(d, last)
        else
          raise FSError.new("Password list for #{name} is empty")
        end
      else
        raise FSError.new("No such password: #{name}")
      end
    end

    def store(name, str)
      d = File.join(dir, name)
      p = File.join(dir, name, Time.now.utc.iso8601)
      FileUtils.mkdir_p(d)
      File.open(p, 'w') {|f| f.write(str)}
      commit(d, p)
    end
  end

  module Crypto
    extend self

    def encrypt(str)
      RubyGpg.encrypt_string(str, Config.key, :armor => true)
    end

    def decrypt(str)
      RubyGpg.decrypt_string(str)
    end
  end

  module Gen
    def self.randstr(len=12)
      str = SecureRandom.random_bytes(len * 24).gsub(/[^A-Za-z0-9_]/, '')
      if str.size >= len
        str[0..(len-1)]
      else
        # should basically never happen
        randstr(len, opts)
      end
    end
  end

  def self.get
    if k = ARGV.shift
      fn = FS.latest(k)
      puts "Reading #{fn}..."
      puts Crypto.decrypt(File.read(fn))
    else
      usage
    end
  end

  def self.set
    if k = ARGV.shift
      puts "Reading data up to EOF..."
      FS.store(k, Crypto.encrypt($stdin.read))
      puts "Stored as #{k}"
    else
      usage
    end
  end

  def self.gen
    puts Gen.randstr
  end

  def self.ls
    pws = FS.passwords
    puts pws.join("\n") unless pws.empty?
  end

  def self.usage
    $stderr.puts "#{File.basename($0)} [get|set|ls] [key]"
  end

  def self.init
    if File.directory?(FS.dir)
      $stderr.puts "#{FS.dir} already exists"
    else
      FS.init
    end
  end

  def self.main
    case ARGV.shift
    when 'get' then get
    when 'set' then set
    when 'ls' then ls
    when 'gen' then gen
    when 'init' then init
    else ls; usage
    end
  end
end

VaultBox.main if $0 == __FILE__
