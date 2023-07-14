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

# we disable autocomplete since it won't work in the Ghidra interpreter window
IRB.conf[:USE_AUTOCOMPLETE] = false
IRB.conf[:USE_MULTILINE] = false

# this was copied from
# https://github.com/ruby/irb/blob/ed9e435a6beba805b3a8b453369cc6117ec7e377/lib/irb/init.rb#L398
module IRB
  # enumerate possible rc-file base name generators
  def IRB.rc_file_generators
    if irbrc = ENV["IRBRC"]
      yield proc{|rc| rc == "rc" ? irbrc : irbrc+rc}
    end
    if xdg_config_home = ENV["XDG_CONFIG_HOME"]
      irb_home = File.join(xdg_config_home, "irb")
      if File.directory?(irb_home)
        yield proc{|rc| irb_home + "/irb#{rc}"}
      end
    end
    if home = ENV["HOME"]
      yield proc{|rc| home+"/.irb#{rc}"}
    end

    # TODO: I'd love to do this, but this isn't available at startup
#   current_dir = project_root_folder.project_locator.project_dir.to_s
    current_dir = Dir.pwd

#   yield proc{|rc| current_dir+"/.config/irb/irb#{rc}"}
    yield proc{|rc| current_dir+"/.irb#{rc}"}
#   yield proc{|rc| current_dir+"/irb#{rc.sub(/\A_?/, '.')}"}
#   yield proc{|rc| current_dir+"/_irb#{rc}"}
#   yield proc{|rc| current_dir+"/$irb#{rc}"}
  end
end

# due to differing output and specialization, have a custom irbrc name
# we suppress the constant override warning from this reassignment by
# temporarily altering the verbosity level
current_verbose = $VERBOSE
$VERBOSE = nil
IRB::IRBRC_EXT = "rc-ghidra"
$VERBOSE = current_verbose
