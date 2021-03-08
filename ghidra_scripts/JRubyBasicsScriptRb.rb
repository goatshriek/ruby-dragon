# Examples of JRuby-specific functionality
# @category: Examples.Ruby

# you'll still need to import any Java classes you use
java_import 'java.util.LinkedList'

# using Java data structures from JRuby
ruby_list = [1,2,3] 
print 'ruby array class name: ', ruby_list.class, "\n"
java_list = LinkedList.new([1,2,3])
print 'java list class name: ', java_list.class, "\n"

# standard Ruby syntactical sugar with Java objects
puts
print 'element 0: ', java_list[0], "\n"
print 'elements 0 and 1: ', java_list[0,2], "\n"

# you can iterate over Java collections in the natural Ruby way
puts
puts 'all items in the java list:'
java_list.each {|item| puts item}

# and of course, you can do other Ruby things on these objects
puts
print 'does the java list have 2?: ', java_list.include?(2), "\n"
print 'does the java list have \'two\'?: ', java_list.include?('two'), "\n"

# expected script output:
=begin
ruby array class name: Array
java list class name: Java::JavaUtil::LinkedList

element 0: 1
elements 0 and 1: [1, 2]

all items in the java list:
1
2
3

does the java list have 2?: true
does the java list have 'two'?: false
=end