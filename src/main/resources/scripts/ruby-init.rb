require 'irb'
require 'irb/completion'

# allow java-like package names, and import irb and completions
def ghidra
	Java::ghidra
end

#ghidra classes (mostly) have good toString values meant for jython, so just use them vs useless java class inspect
class java::lang::Object
	def inspect(*args)
		return self.class.name.start_with?("Java::Ghidra") ? "#<#{to_string}>" : super(*args)
	end
end

# Now configure IRB

# JRuby-9.3 ships with a slightly broken irb, and we want to modify it anyway, so look at
# https://github.com/ruby/irb/blob/master/lib/irb/init.rb#L367 where this was copied from
module IRB
  # enumerate possible rc-file base name generators
  def IRB.rc_file_generators
    if irbrc = ENV["IRBRC"]
      yield proc{|rc| rc == "rc" ? irbrc : irbrc+rc}
    end
    if xdg_config_home = ENV["XDG_CONFIG_HOME"]
      irb_home = File.join(xdg_config_home, "ghidra")
      unless File.exist? irb_home
        require 'fileutils'
        FileUtils.mkdir_p irb_home
      end
      yield proc{|rc| irb_home + "/irb#{rc}"}
    end
    if home = ENV["HOME"]
      yield proc{|rc| home+"/.irb#{rc}"}
    end
    # TODO: I'd love to do this, but this isn't available at startup
#    current_dir = project_root_folder.project_locator.project_dir.to_s
	current_dir = Dir.pwd
#    yield proc{|rc| current_dir+"/.config/irb/irb#{rc}"}
    yield proc{|rc| current_dir+"/.irb#{rc}"}
#    yield proc{|rc| current_dir+"/irb#{rc.sub(/\A_?/, '.')}"}
#    yield proc{|rc| current_dir+"/_irb#{rc}"}
#    yield proc{|rc| current_dir+"/$irb#{rc}"}
  end
end

# due to differing output and specialization, have a custom irbrc name
IRB::IRBRC_EXT = "rc-ghidra"
# TODO: supress constant override warning above

