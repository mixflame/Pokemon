#!/usr/bin/env ruby

$required_libs = []

RUBYMOTION_GEM_CONFIG = <<-HEREDOC
Motion::Project::App.setup do |app|
  MAIN_CONFIG_FILES
end
HEREDOC

INCLUDE_STRING = "    app.files << File.expand_path(File.join(File.dirname(__FILE__),'RELATIVE_LIBRARY_PATH'))"

def require(file)
  #puts file
  if !$required_libs.include?(file) #file.include?(ARGV[1]) && file != ARGV[0]
    file_index = $required_libs.count - 1
    $required_libs.insert file_index, INCLUDE_STRING.gsub("RELATIVE_LIBRARY_PATH", file)
  end

  super file
end


require(ARGV[0])


@manifest = RUBYMOTION_GEM_CONFIG.gsub("MAIN_CONFIG_FILES", $required_libs.join("\n"))


puts @manifest
