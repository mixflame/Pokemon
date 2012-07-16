#!/usr/bin/env ruby

#require 'rubygems'
require 'pathname'

$uniq_libs = []

$required_libs = []

@master_file = ""


# fake require so we dont raise in rubymotion
fake_require = <<-HEREDOC
def require(file)
  # no-op
end
HEREDOC

@master_file += fake_require

def require(file)
  $LOAD_PATH.each do |path|
    lib_file = File.join(path, "#{file}.rb")
    if File.exists?(lib_file)
      unless $uniq_libs.include?(file)
        file_index = $required_libs.count - 1
        $uniq_libs << file
        $required_libs.insert file_index, lib_file # i will changing to insert now and proper load order
      end
    end
  end
  super file
end

require(ARGV[0])

$required_libs.each do |lib_file|
  s = File.open(lib_file, "r").read
  @master_file += s #"#{s}\n" + @master_file
end

# p $required_libs

puts @master_file
