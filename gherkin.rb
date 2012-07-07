module Gherkin
  module Formatter
    class Hashable
      def to_hash
        instance_variables.inject({}) do |hash, ivar|
          value = instance_variable_get(ivar)
          value = value.to_hash if value.respond_to?(:to_hash)
          if Array === value
            value = value.map do |e|
              e.respond_to?(:to_hash) ? e.to_hash : e
            end
          end
          hash[ivar[1..-1]] = value unless [[], nil].index(value)
          hash
        end
      end
    end
  end
end
require 'gherkin/native'
require 'gherkin/formatter/hashable'

module Gherkin
  module Formatter
    module Model
      class BasicStatement < Hashable
        attr_reader :comments, :keyword, :name, :line
        
        def initialize(comments, keyword, name, line)
          @comments, @keyword, @name, @line = comments, keyword, name, line
        end

        def line_range
          first = @comments.any? ? @comments[0].line : first_non_comment_line
          first..line
        end

        def first_non_comment_line
          @line
        end
      end

      class DescribedStatement < BasicStatement
        attr_reader :description

        def initialize(comments, keyword, name, description, line)
          super(comments, keyword, name, line)
          @description = description
        end
      end

      class TagStatement < DescribedStatement
        attr_reader :tags, :id

        def initialize(comments, tags, keyword, name, description, line, id)
          super(comments, keyword, name, description, line)
          @tags = tags
          @id = id
        end

        def first_non_comment_line
          @tags.any? ? @tags[0].line : @line
        end
      end

      class Feature < TagStatement
        native_impl('gherkin')

        def replay(formatter)
          formatter.feature(self)
        end
      end

      class Background < DescribedStatement
        native_impl('gherkin')

        def initialize(comments, keyword, name, description, line)
          super(comments, keyword, name, description, line)
          @type = "background"
        end

        def replay(formatter)
          formatter.background(self)
        end
      end

      class Scenario < TagStatement
        native_impl('gherkin')

        def initialize(comments, tags, keyword, name, description, line, id)
          super(comments, tags, keyword, name, description, line, id)
          @type = "scenario"
        end

        def replay(formatter)
          formatter.scenario(self)
        end
      end

      class ScenarioOutline < TagStatement
        native_impl('gherkin')

        def initialize(comments, tags, keyword, name, description, line, id)
          super(comments, tags, keyword, name, description, line, id)
          @type = "scenario_outline"
        end

        def replay(formatter)
          formatter.scenario_outline(self)
        end
      end

      class Examples < TagStatement
        native_impl('gherkin')

        attr_accessor :rows # needs to remain mutable for filters

        def initialize(comments, tags, keyword, name, description, line, id, rows)
          super(comments, tags, keyword, name, description, line, id)
          @rows = rows
        end

        def replay(formatter)
          formatter.examples(self)
        end
        
        class Builder
          def initialize(*args)
            @args = *args
            @rows = nil
          end
        
          def row(comments, cells, line, id)
            @rows ||= []
            @rows << ExamplesTableRow.new(comments, cells, line, id)
          end
        
          def replay(formatter)
            build.replay(formatter)
          end
          
          def build
            Examples.new(*(@args << @rows))
          end
        end
      end

      class Step < BasicStatement
        native_impl('gherkin')

        attr_reader :rows, :doc_string
        
        def initialize(comments, keyword, name, line, rows, doc_string)
          super(comments, keyword, name, line)
          @rows, @doc_string = rows, doc_string
        end

        def line_range
          range = super
          if(rows)
            range = range.first..rows[-1].line
          elsif(doc_string)
            range = range.first..doc_string.line_range.last
          end
          range
        end

        def replay(formatter)
          formatter.step(self)
        end

        def outline_args
          offset = 0
          name.scan(/<[^<]*>/).map do |val|
            offset = name.index(val, offset)
            Argument.new(offset, val)
          end
        end
        
        class Builder
          def initialize(*args)
            @args = *args
            @rows = nil
            @doc_string = nil
          end
        
          def row(comments, cells, line, id)
            @rows ||= []
            @rows << DataTableRow.new(comments, cells, line)
          end
          
          def doc_string(string, content_type, line)
            @doc_string = Formatter::Model::DocString.new(string, content_type, line)
          end
        
          def replay(formatter)
            build.replay(formatter)
          end
          
          def build
            Step.new(*(@args << @rows << @doc_string))
          end
        end
      end

      class Comment < Hashable
        native_impl('gherkin')

        attr_reader :value, :line
        
        def initialize(value, line)
          @value, @line = value, line
        end
      end

      class Tag < Hashable
        native_impl('gherkin')

        attr_reader :name, :line
        
        def initialize(name, line)
          @name, @line = name, line
        end
        
        def eql?(tag)
          @name.eql?(tag.name)
        end

        def hash
          @name.hash
        end
      end

      class DocString < Hashable
        native_impl('gherkin')

        attr_reader :value, :content_type, :line
        
        def initialize(value, content_type, line)
          @value, @content_type, @line = value, content_type, line
        end

        def line_range
          line_count = value.split(/\r?\n/).length
          line..(line+line_count+1)
        end
      end

      class Row < Hashable
        attr_reader :comments, :cells, :line

        def initialize(comments, cells, line)
          @comments, @cells, @line = comments, cells, line
        end
      end

      class DataTableRow < Row
        native_impl('gherkin')
      end

      class ExamplesTableRow < Row
        native_impl('gherkin')
        attr_reader :id

        def initialize(comments, cells, line, id)
          super(comments, cells, line)
          @id = id
        end
      end

      class Match < Hashable
        native_impl('gherkin')

        attr_reader :arguments, :location
        
        def initialize(arguments, location)
          @arguments, @location = arguments, location
        end

        def replay(formatter)
          formatter.match(self)
        end
      end

      class Result < Hashable
        native_impl('gherkin')

        attr_reader :status, :duration, :error_message
        
        def initialize(status, duration, error_message)
          @status, @duration, @error_message = status, duration, error_message
        end

        def replay(formatter)
          formatter.result(self)
        end
      end
    end
  end
end

require 'gherkin/native'
require 'gherkin/formatter/model'

module Gherkin
  module Listener
    # Adapter from the "raw" Gherkin <tt>Listener</tt> API
    # to the slightly more high-level <tt>Formatter</tt> API,
    # which is easier to implement (less state to keep track of).
    class FormatterListener
      native_impl('gherkin')

      def initialize(formatter)
        @formatter = formatter
        @stash = Stash.new
      end

      def comment(value, line)
        @stash.comment Formatter::Model::Comment.new(value, line)
      end

      def tag(name, line)
        @stash.tag Formatter::Model::Tag.new(name, line)
      end

      def feature(keyword, name, description, line)
        @stash.feature(name) do |comments, tags, id|
          replay Formatter::Model::Feature.new(comments, tags, keyword, name, description, line, id)
        end
      end

      def background(keyword, name, description, line)
        @stash.feature_element(name) do |comments, tags, id|
          replay Formatter::Model::Background.new(comments, keyword, name, description, line)
        end
      end

      def scenario(keyword, name, description, line)
        replay_step_or_examples
        @stash.feature_element(name) do |comments, tags, id|
          replay Formatter::Model::Scenario.new(comments, tags, keyword, name, description, line, id)
        end
      end

      def scenario_outline(keyword, name, description, line)
        replay_step_or_examples
        @stash.feature_element(name) do |comments, tags, id|
          replay Formatter::Model::ScenarioOutline.new(comments, tags, keyword, name, description, line, id)
        end
      end

      def examples(keyword, name, description, line)
        replay_step_or_examples
        @stash.examples(name) do |comments, tags, id|
          @current_builder = Formatter::Model::Examples::Builder.new(comments, tags, keyword, name, description, line, id)
        end
      end

      def step(keyword, name, line)
        replay_step_or_examples
        @stash.basic_statement do |comments, id|
          @current_builder = Formatter::Model::Step::Builder.new(comments, keyword, name, line)
        end
      end

      def row(cells, line)
        @stash.basic_statement do |comments, id|
          @current_builder.row(comments, cells, line, id)
        end
      end

      def doc_string(content_type, value, line)
        @current_builder.doc_string(value, content_type, line)
      end

      def eof
        replay_step_or_examples
        @formatter.eof
      end

      def syntax_error(state, ev, legal_events, uri, line)
        @formatter.syntax_error(state, ev, legal_events, uri, line)
      end

    private
    
      def replay(element)
        element.replay(@formatter)
      end
      
      class Stash
        attr_reader :comments, :tags, :ids
        
        def initialize
          @comments, @tags, @ids = [], [], []
          @row_index = 0
        end
        
        def comment(comment)
          @comments << comment
        end
        
        def feature(name)
          @feature_id = id(name)
          yield @comments, @tags, @feature_id
          @comments, @tags = [], []
        end

        def feature_element(name)
          @feature_element_id = "#{@feature_id};#{id(name)}"
          yield @comments, @tags, @feature_element_id
          @comments, @tags = [], []
        end
        
        def examples(name)
          @examples_id = "#{@feature_element_id};#{id(name)}"
          @row_index = 0
          yield @comments, @tags, @examples_id
          @comments, @tags = [], []
        end
        
        def basic_statement
          @row_index += 1
          yield @comments, "#{@examples_id};#{@row_index}"
          @comments = []
        end
        
        def tag(tag)
          @tags << tag
        end

        def id(name)
          (name || '').gsub(/[\s_]/, '-').downcase
        end
      end

      def replay_step_or_examples
        return unless @current_builder
        replay(@current_builder)
        @current_builder = nil
      end
    end
  end
end

require 'gherkin/i18n'
require 'gherkin/lexer/i18n_lexer'
require 'gherkin/native'
require 'gherkin/listener/formatter_listener'

module Gherkin
  module Parser
    class ParseError < StandardError
      def initialize(state, new_state, expected_states, uri, line)
        super("Parse error at #{uri}:#{line}. Found #{new_state} when expecting one of: #{expected_states.join(', ')}. (Current state: #{state}).")
      end
    end

    class Parser
      native_impl('gherkin')

      # Initialize the parser. +machine_name+ refers to a state machine table.
      def initialize(formatter, raise_on_error=true, machine_name='root', force_ruby=false)
        @formatter = formatter
        @listener = Listener::FormatterListener.new(@formatter)
        @raise_on_error = raise_on_error
        @machine_name = machine_name
        @machines = []
        push_machine(@machine_name)
        @lexer = Gherkin::Lexer::I18nLexer.new(self, force_ruby)
      end

      def parse(gherkin, feature_uri, line_offset)
        @formatter.uri(feature_uri)
        @line_offset = line_offset
        @lexer.scan(gherkin)
      end

      def i18n_language
        @lexer.i18n_language
      end

      def errors
        @lexer.errors
      end

      # Doesn't yet fall back to super
      def method_missing(method, *args)
        # TODO: Catch exception and call super
        event(method.to_s, args[-1])
        @listener.__send__(method, *args)
        if method == :eof
          pop_machine
          push_machine(@machine_name)
        end
      end

      def event(ev, line)
        l = line ? @line_offset+line : nil
        machine.event(ev, l) do |state, legal_events|
          if @raise_on_error
            raise ParseError.new(state, ev, legal_events, @feature_uri, l)
          else
            # Only used for testing
            @listener.syntax_error(state, ev, legal_events, @feature_uri, l)
          end
        end
      end

      def push_machine(name)
        @machines.push(Machine.new(self, name))
      end

      def pop_machine
        @machines.pop
      end

      def machine
        @machines[-1]
      end

      def expected
        machine.expected
      end

      def force_state(state)
        machine.instance_variable_set('@state', state)
      end

      class Machine
        def initialize(parser, name)
          @parser = parser
          @name = name
          @transition_map = transition_map(name)
          @state = name
        end

        def event(ev, line)
          states = @transition_map[@state]
          raise "Unknown state: #{@state.inspect} for machine #{@name}" if states.nil?
          new_state = states[ev]
          case new_state
          when "E"
            yield @state, expected
          when /push\((.+)\)/
            @parser.push_machine($1)
            @parser.event(ev, line)
          when "pop()"
            @parser.pop_machine()
            @parser.event(ev, line)
          else
            raise "Unknown transition: #{ev.inspect} among #{states.inspect} for machine #{@name}" if new_state.nil?
            @state = new_state
          end
        end

        def expected
          allowed = @transition_map[@state].find_all { |_, action| action != "E" }
          allowed.collect { |state| state[0] }.sort - ['eof']
        end

        private

        @@transition_maps = {}

        def transition_map(name)
          @@transition_maps[name] ||= build_transition_map(name)
        end

        def build_transition_map(name)
          table = transition_table(name)
          events = table.shift[1..-1]
          table.inject({}) do |machine, actions|
            state = actions.shift
            machine[state] = Hash[*events.zip(actions).flatten]
            machine
          end
        end

        def transition_table(name)
          state_machine_reader = StateMachineReader.new
          lexer = Gherkin::I18n.new('en').lexer(state_machine_reader)
          machine = File.dirname(__FILE__) + "/#{name}.txt"
          lexer.scan(File.read(machine))
          state_machine_reader.rows
        end

        class StateMachineReader
          attr_reader :rows

          def initialize
            @rows = []
          end

          def uri(uri)
          end

          def row(row, line_number)
            @rows << row
          end

          def eof
          end
        end

      end
    end
  end
end

class Class
  def native_impl(lib)
    # no-op
  end
end

if defined?(JRUBY_VERSION)
  require 'gherkin/native/java'
elsif ENV['GHERKIN_JS_NATIVE']
  require 'gherkin/native/therubyracer'
else
  require 'gherkin/native/null'
end

module Gherkin
  module Rubify
    if defined?(JRUBY_VERSION)
      # Translate Java objects to Ruby.
      # This is especially important to convert java.util.List coming
      # from Java and back to a Ruby Array.
      def rubify(o)
        case(o)
        when Java.java.util.Collection, Array
          o.map{|e| rubify(e)}
        when Java.gherkin.formatter.model.DocString
          require 'gherkin/formatter/model'
          Formatter::Model::DocString.new(o.content_type, o.value, o.line)
        else
          o
        end
      end
    else
      def rubify(o)
        o
      end
    end
  end
end
require 'psych/tree_builder'

module Psych
  module Handlers
    class DocumentStream < Psych::TreeBuilder # :nodoc:
      def initialize &block
        super
        @block = block
      end

      def start_document version, tag_directives, implicit
        n = Nodes::Document.new version, tag_directives, implicit
        push n
      end

      def end_document implicit_end = !streaming?
        @last.implicit_end = implicit_end
        @block.call pop
      end
    end
  end
end

require 'psych/json/ruby_events'
require 'psych/json/yaml_events'

module Psych
  module JSON
    class Stream < Psych::Visitors::JSONTree
      include Psych::JSON::RubyEvents
      include Psych::Streaming

      class Emitter < Psych::Stream::Emitter # :nodoc:
        include Psych::JSON::YAMLEvents
      end
    end
  end
end

module Psych
  module JSON
    module YAMLEvents # :nodoc:
      def start_document version, tag_directives, implicit
        super(version, tag_directives, !streaming?)
      end

      def end_document implicit_end = !streaming?
        super(implicit_end)
      end

      def start_mapping anchor, tag, implicit, style
        super(anchor, nil, implicit, Nodes::Mapping::FLOW)
      end

      def start_sequence anchor, tag, implicit, style
        super(anchor, nil, implicit, Nodes::Sequence::FLOW)
      end

      def scalar value, anchor, tag, plain, quoted, style
        if "tag:yaml.org,2002:null" == tag
          super('null', nil, nil, true, false, Nodes::Scalar::PLAIN)
        else
          super
        end
      end
    end
  end
end

require 'psych/json/yaml_events'

module Psych
  module JSON
    ###
    # Psych::JSON::TreeBuilder is an event based AST builder.  Events are sent
    # to an instance of Psych::JSON::TreeBuilder and a JSON AST is constructed.
    class TreeBuilder < Psych::TreeBuilder
      include Psych::JSON::YAMLEvents
    end
  end
end

module Psych
  ###
  # Psych::Stream is a streaming YAML emitter.  It will not buffer your YAML,
  # but send it straight to an IO.
  #
  # Here is an example use:
  #
  #   stream = Psych::Stream.new($stdout)
  #   stream.start
  #   stream.push({:foo => 'bar'})
  #   stream.finish
  #
  # YAML will be immediately emitted to $stdout with no buffering.
  #
  # Psych::Stream#start will take a block and ensure that Psych::Stream#finish
  # is called, so you can do this form:
  #
  #   stream = Psych::Stream.new($stdout)
  #   stream.start do |em|
  #     em.push(:foo => 'bar')
  #   end
  #
  class Stream < Psych::Visitors::YAMLTree
    class Emitter < Psych::Emitter # :nodoc:
      def end_document implicit_end = !streaming?
        super
      end

      def streaming?
        true
      end
    end

    include Psych::Streaming
  end
end

# format.rb: Written by Tadayoshi Funaba 1999-2011

# date.rb: Written by Tadayoshi Funaba 1998-2011

require 'date_core'
require 'date/format'

class Date

  class Infinity < Numeric # :nodoc:

    include Comparable

    def initialize(d=1) @d = d <=> 0 end

    def d() @d end

    protected :d

    def zero? () false end
    def finite? () false end
    def infinite? () d.nonzero? end
    def nan? () d.zero? end

    def abs() self.class.new end

    def -@ () self.class.new(-d) end
    def +@ () self.class.new(+d) end

    def <=> (other)
      case other
      when Infinity; return d <=> other.d
      when Numeric; return d
      else
	begin
	  l, r = other.coerce(self)
	  return l <=> r
	rescue NoMethodError
	end
      end
      nil
    end

    def coerce(other)
      case other
      when Numeric; return -d, d
      else
	super
      end
    end

    def to_f
      return 0 if @d == 0
      if @d > 0
	Float::INFINITY
      else
	-Float::INFINITY
      end
    end

  end

end

require 'date'

module Psych
  DEPRECATED = __FILE__ # :nodoc:

  module DeprecatedMethods # :nodoc:
    attr_accessor :taguri
    attr_accessor :to_yaml_style
  end

  def self.quick_emit thing, opts = {}, &block # :nodoc:
    warn "#{caller[0]}: YAML.quick_emit is deprecated" if $VERBOSE && !caller[0].start_with?(File.dirname(__FILE__))
    target = eval 'self', block.binding
    target.extend DeprecatedMethods
    metaclass = class << target; self; end
    metaclass.send(:define_method, :encode_with) do |coder|
      target.taguri        = coder.tag
      target.to_yaml_style = coder.style
      block.call coder
    end
    target.psych_to_yaml unless opts[:nodump]
  end

  def self.load_documents yaml, &block
    if $VERBOSE
      warn "#{caller[0]}: load_documents is deprecated, use load_stream"
    end
    list = load_stream yaml
    return list unless block_given?
    list.each(&block)
  end

  def self.detect_implicit thing
    warn "#{caller[0]}: detect_implicit is deprecated" if $VERBOSE
    return '' unless String === thing
    return 'null' if '' == thing
    ScalarScanner.new.tokenize(thing).class.name.downcase
  end

  def self.add_ruby_type type_tag, &block
    warn "#{caller[0]}: add_ruby_type is deprecated, use add_domain_type" if $VERBOSE
    domain = 'ruby.yaml.org,2002'
    key = ['tag', domain, type_tag].join ':'
    @domain_types[key] = [key, block]
  end

  def self.add_private_type type_tag, &block
    warn "#{caller[0]}: add_private_type is deprecated, use add_domain_type" if $VERBOSE
    domain = 'x-private'
    key = [domain, type_tag].join ':'
    @domain_types[key] = [key, block]
  end

  def self.tagurize thing
    warn "#{caller[0]}: add_private_type is deprecated, use add_domain_type" if $VERBOSE
    return thing unless String === thing
    "tag:yaml.org,2002:#{thing}"
  end

  def self.read_type_class type, reference
    warn "#{caller[0]}: read_type_class is deprecated" if $VERBOSE
    _, _, type, name = type.split ':', 4

    reference = name.split('::').inject(reference) do |k,n|
      k.const_get(n.to_sym)
    end if name
    [type, reference]
  end

  def self.object_maker klass, hash
    warn "#{caller[0]}: object_maker is deprecated" if $VERBOSE
    klass.allocate.tap do |obj|
      hash.each { |k,v| obj.instance_variable_set(:"@#{k}", v) }
    end
  end
end

class Object
  undef :to_yaml_properties rescue nil
  def to_yaml_properties # :nodoc:
    instance_variables
  end
end

class Object
  def self.yaml_tag url
    Psych.add_tag(url, self)
  end

  # FIXME: rename this to "to_yaml" when syck is removed

  ###
  # call-seq: to_yaml(options = {})
  #
  # Convert an object to YAML.  See Psych.dump for more information on the
  # available +options+.
  def psych_to_yaml options = {}
    Psych.dump self, options
  end
  remove_method :to_yaml rescue nil
  alias :to_yaml :psych_to_yaml
end

class Module
  def psych_yaml_as url
    return if caller[0].end_with?('rubytypes.rb')
    if $VERBOSE
      warn "#{caller[0]}: yaml_as is deprecated, please use yaml_tag"
    end
    Psych.add_tag(url, self)
  end

  remove_method :yaml_as rescue nil
  alias :yaml_as :psych_yaml_as
end

if defined?(::IRB)
module Kernel
  def psych_y *objects
    puts Psych.dump_stream(*objects)
  end
  remove_method :y rescue nil
  alias y psych_y
  private :y
end
end

module Psych
  ###
  # If an object defines +encode_with+, then an instance of Psych::Coder will
  # be passed to the method when the object is being serialized.  The Coder
  # automatically assumes a Psych::Nodes::Mapping is being emitted.  Other
  # objects like Sequence and Scalar may be emitted if +seq=+ or +scalar=+ are
  # called, respectively.
  class Coder
    attr_accessor :tag, :style, :implicit, :object
    attr_reader   :type, :seq

    def initialize tag
      @map      = {}
      @seq      = []
      @implicit = false
      @type     = :map
      @tag      = tag
      @style    = Psych::Nodes::Mapping::BLOCK
      @scalar   = nil
      @object   = nil
    end

    def scalar *args
      if args.length > 0
        warn "#{caller[0]}: Coder#scalar(a,b,c) is deprecated" if $VERBOSE
        @tag, @scalar, _ = args
        @type = :scalar
      end
      @scalar
    end

    # Emit a map.  The coder will be yielded to the block.
    def map tag = @tag, style = @style
      @tag   = tag
      @style = style
      yield self if block_given?
      @map
    end

    # Emit a scalar with +value+ and +tag+
    def represent_scalar tag, value
      self.tag    = tag
      self.scalar = value
    end

    # Emit a sequence with +list+ and +tag+
    def represent_seq tag, list
      @tag = tag
      self.seq = list
    end

    # Emit a sequence with +map+ and +tag+
    def represent_map tag, map
      @tag = tag
      self.map = map
    end

    # Emit an arbitrary object +obj+ and +tag+
    def represent_object tag, obj
      @tag    = tag
      @type   = :object
      @object = obj
    end

    # Emit a scalar with +value+
    def scalar= value
      @type   = :scalar
      @scalar = value
    end

    # Emit a map with +value+
    def map= map
      @type = :map
      @map  = map
    end

    def []= k, v
      @type = :map
      @map[k] = v
    end
    alias :add :[]=

    def [] k
      @type = :map
      @map[k]
    end

    # Emit a sequence of +list+
    def seq= list
      @type = :seq
      @seq  = list
    end
  end
end

module Psych
  class Set < ::Hash
  end
end

module Psych
  class Omap < ::Hash
  end
end

module Psych
  ###
  # YAML event parser class.  This class parses a YAML document and calls
  # events on the handler that is passed to the constructor.  The events can
  # be used for things such as constructing a YAML AST or deserializing YAML
  # documents.  It can even be fed back to Psych::Emitter to emit the same
  # document that was parsed.
  #
  # See Psych::Handler for documentation on the events that Psych::Parser emits.
  #
  # Here is an example that prints out ever scalar found in a YAML document:
  #
  #   # Handler for detecting scalar values
  #   class ScalarHandler < Psych::Handler
  #     def scalar value, anchor, tag, plain, quoted, style
  #       puts value
  #     end
  #   end
  #
  #   parser = Psych::Parser.new(ScalarHandler.new)
  #   parser.parse(yaml_document)
  #
  # Here is an example that feeds the parser back in to Psych::Emitter.  The
  # YAML document is read from STDIN and written back out to STDERR:
  #
  #   parser = Psych::Parser.new(Psych::Emitter.new($stderr))
  #   parser.parse($stdin)
  #
  # Psych uses Psych::Parser in combination with Psych::TreeBuilder to
  # construct an AST of the parsed YAML document.

  class Parser
    class Mark < Struct.new(:index, :line, :column)
    end

    # The handler on which events will be called
    attr_accessor :handler

    # Set the encoding for this parser to +encoding+
    attr_writer :external_encoding

    ###
    # Creates a new Psych::Parser instance with +handler+.  YAML events will
    # be called on +handler+.  See Psych::Parser for more details.

    def initialize handler = Handler.new
      @handler = handler
      @external_encoding = ANY
    end
  end
end

require 'psych/handler'

module Psych
  ###
  # This class works in conjunction with Psych::Parser to build an in-memory
  # parse tree that represents a YAML document.
  #
  # == Example
  #
  #   parser = Psych::Parser.new Psych::TreeBuilder.new
  #   parser.parse('--- foo')
  #   tree = parser.handler.root
  #
  # See Psych::Handler for documentation on the event methods used in this
  # class.
  class TreeBuilder < Psych::Handler
    # Returns the root node for the built tree
    attr_reader :root

    # Create a new TreeBuilder instance
    def initialize
      @stack = []
      @last  = nil
      @root  = nil
    end

    %w{
      Sequence
      Mapping
    }.each do |node|
      class_eval %{
        def start_#{node.downcase}(anchor, tag, implicit, style)
          n = Nodes::#{node}.new(anchor, tag, implicit, style)
          @last.children << n
          push n
        end

        def end_#{node.downcase}
          pop
        end
      }
    end

    ###
    # Handles start_document events with +version+, +tag_directives+,
    # and +implicit+ styling.
    #
    # See Psych::Handler#start_document
    def start_document version, tag_directives, implicit
      n = Nodes::Document.new version, tag_directives, implicit
      @last.children << n
      push n
    end

    ###
    # Handles end_document events with +version+, +tag_directives+,
    # and +implicit+ styling.
    #
    # See Psych::Handler#start_document
    def end_document implicit_end = !streaming?
      @last.implicit_end = implicit_end
      pop
    end

    def start_stream encoding
      @root = Nodes::Stream.new(encoding)
      push @root
    end

    def end_stream
      pop
    end

    def scalar value, anchor, tag, plain, quoted, style
      s = Nodes::Scalar.new(value,anchor,tag,plain,quoted,style)
      @last.children << s
      s
    end

    def alias anchor
      @last.children << Nodes::Alias.new(anchor)
    end

    private
    def push value
      @stack.push value
      @last = value
    end

    def pop
      x = @stack.pop
      @last = @stack.last
      x
    end
  end
end

module Psych
  ###
  # Psych::Handler is an abstract base class that defines the events used
  # when dealing with Psych::Parser.  Clients who want to use Psych::Parser
  # should implement a class that inherits from Psych::Handler and define
  # events that they can handle.
  #
  # Psych::Handler defines all events that Psych::Parser can possibly send to
  # event handlers.
  #
  # See Psych::Parser for more details
  class Handler
    ###
    # Called with +encoding+ when the YAML stream starts.  This method is
    # called once per stream.  A stream may contain multiple documents.
    #
    # See the constants in Psych::Parser for the possible values of +encoding+.
    def start_stream encoding
    end

    ###
    # Called when the document starts with the declared +version+,
    # +tag_directives+, if the document is +implicit+.
    #
    # +version+ will be an array of integers indicating the YAML version being
    # dealt with, +tag_directives+ is a list of tuples indicating the prefix
    # and suffix of each tag, and +implicit+ is a boolean indicating whether
    # the document is started implicitly.
    #
    # === Example
    #
    # Given the following YAML:
    #
    #   %YAML 1.1
    #   %TAG ! tag:tenderlovemaking.com,2009:
    #   --- !squee
    #
    # The parameters for start_document must be this:
    #
    #   version         # => [1, 1]
    #   tag_directives  # => [["!", "tag:tenderlovemaking.com,2009:"]]
    #   implicit        # => false
    def start_document version, tag_directives, implicit
    end

    ###
    # Called with the document ends.  +implicit+ is a boolean value indicating
    # whether or not the document has an implicit ending.
    #
    # === Example
    #
    # Given the following YAML:
    #
    #   ---
    #     hello world
    #
    # +implicit+ will be true.  Given this YAML:
    #
    #   ---
    #     hello world
    #   ...
    #
    # +implicit+ will be false.
    def end_document implicit
    end

    ###
    # Called when an alias is found to +anchor+.  +anchor+ will be the name
    # of the anchor found.
    #
    # === Example
    #
    # Here we have an example of an array that references itself in YAML:
    #
    #   --- &ponies
    #   - first element
    #   - *ponies
    #
    # &ponies is the achor, *ponies is the alias.  In this case, alias is
    # called with "ponies".
    def alias anchor
    end

    ###
    # Called when a scalar +value+ is found.  The scalar may have an
    # +anchor+, a +tag+, be implicitly +plain+ or implicitly +quoted+
    #
    # +value+ is the string value of the scalar
    # +anchor+ is an associated anchor or nil
    # +tag+ is an associated tag or nil
    # +plain+ is a boolean value
    # +quoted+ is a boolean value
    # +style+ is an integer idicating the string style
    #
    # See the constants in Psych::Nodes::Scalar for the possible values of
    # +style+
    #
    # === Example
    #
    # Here is a YAML document that exercises most of the possible ways this
    # method can be called:
    #
    #   ---
    #   - !str "foo"
    #   - &anchor fun
    #   - many
    #     lines
    #   - |
    #     many
    #     newlines
    #
    # The above YAML document contains a list with four strings.  Here are
    # the parameters sent to this method in the same order:
    #
    #   # value               anchor    tag     plain   quoted  style
    #   ["foo",               nil,      "!str", false,  false,  3    ]
    #   ["fun",               "anchor", nil,    true,   false,  1    ]
    #   ["many lines",        nil,      nil,    true,   false,  1    ]
    #   ["many\nnewlines\n",  nil,      nil,    false,  true,   4    ]
    #
    def scalar value, anchor, tag, plain, quoted, style
    end

    ###
    # Called when a sequence is started.
    #
    # +anchor+ is the anchor associated with the sequence or nil.
    # +tag+ is the tag associated with the sequence or nil.
    # +implicit+ a boolean indicating whether or not the sequence was implicitly
    # started.
    # +style+ is an integer indicating the list style.
    #
    # See the constants in Psych::Nodes::Sequence for the possible values of
    # +style+.
    #
    # === Example
    #
    # Here is a YAML document that exercises most of the possible ways this
    # method can be called:
    #
    #   ---
    #   - !!seq [
    #     a
    #   ]
    #   - &pewpew
    #     - b
    #
    # The above YAML document consists of three lists, an outer list that
    # contains two inner lists.  Here is a matrix of the parameters sent
    # to represent these lists:
    #
    #   # anchor    tag                       implicit  style
    #   [nil,       nil,                      true,     1     ]
    #   [nil,       "tag:yaml.org,2002:seq",  false,    2     ]
    #   ["pewpew",  nil,                      true,     1     ]

    def start_sequence anchor, tag, implicit, style
    end

    ###
    # Called when a sequence ends.
    def end_sequence
    end

    ###
    # Called when a map starts.
    #
    # +anchor+ is the anchor associated with the map or +nil+.
    # +tag+ is the tag associated with the map or +nil+.
    # +implicit+ is a boolean indicating whether or not the map was implicitly
    # started.
    # +style+ is an integer indicating the mapping style.
    #
    # See the constants in Psych::Nodes::Mapping for the possible values of
    # +style+.
    #
    # === Example
    #
    # Here is a YAML document that exercises most of the possible ways this
    # method can be called:
    #
    #   ---
    #   k: !!map { hello: world }
    #   v: &pewpew
    #     hello: world
    #
    # The above YAML document consists of three maps, an outer map that contains
    # two inner maps.  Below is a matrix of the parameters sent in order to
    # represent these three maps:
    #
    #   # anchor    tag                       implicit  style
    #   [nil,       nil,                      true,     1     ]
    #   [nil,       "tag:yaml.org,2002:map",  false,    2     ]
    #   ["pewpew",  nil,                      true,     1     ]

    def start_mapping anchor, tag, implicit, style
    end

    ###
    # Called when a map ends
    def end_mapping
    end

    ###
    # Called when an empty event happens. (Which, as far as I can tell, is
    # never).
    def empty
    end

    ###
    # Called when the YAML stream ends
    def end_stream
    end

    ###
    # Is this handler a streaming handler?
    def streaming?
      false
    end
  end
end

module Psych
  module Visitors
    class DepthFirst < Psych::Visitors::Visitor
      def initialize block
        @block = block
      end

      private

      def nary o
        o.children.each { |x| visit x }
        @block.call o
      end
      alias :visit_Psych_Nodes_Stream   :nary
      alias :visit_Psych_Nodes_Document :nary
      alias :visit_Psych_Nodes_Sequence :nary
      alias :visit_Psych_Nodes_Mapping  :nary

      def terminal o
        @block.call o
      end
      alias :visit_Psych_Nodes_Scalar :terminal
      alias :visit_Psych_Nodes_Alias  :terminal
    end
  end
end

module Psych
  module JSON
    module RubyEvents # :nodoc:
      def visit_Time o
        formatted = format_time o
        @emitter.scalar formatted, nil, nil, false, true, Nodes::Scalar::DOUBLE_QUOTED
      end

      def visit_DateTime o
        visit_Time o.to_time
      end

      def visit_String o
        @emitter.scalar o.to_s, nil, nil, false, true, Nodes::Scalar::DOUBLE_QUOTED
      end
      alias :visit_Symbol :visit_String
    end
  end
end

require 'psych/json/ruby_events'

module Psych
  module Visitors
    class JSONTree < YAMLTree
      include Psych::JSON::RubyEvents

      def initialize options = {}, emitter = Psych::JSON::TreeBuilder.new
        super
      end

      def accept target
        if target.respond_to?(:encode_with)
          dump_coder target
        else
          send(@dispatch_cache[target.class], target)
        end
      end
    end
  end
end

module Psych
  module Visitors
    ###
    # YAMLTree builds a YAML ast given a ruby object.  For example:
    #
    #   builder = Psych::Visitors::YAMLTree.new
    #   builder << { :foo => 'bar' }
    #   builder.tree # => #<Psych::Nodes::Stream .. }
    #
    class YAMLTree < Psych::Visitors::Visitor
      attr_reader :started, :finished
      alias :finished? :finished
      alias :started? :started

      def initialize options = {}, emitter = TreeBuilder.new, ss = ScalarScanner.new
        super()
        @started  = false
        @finished = false
        @emitter  = emitter
        @st       = {}
        @ss       = ss
        @options  = options

        @dispatch_cache = Hash.new do |h,klass|
          method = "visit_#{(klass.name || '').split('::').join('_')}"

          method = respond_to?(method) ? method : h[klass.superclass]

          raise(TypeError, "Can't dump #{target.class}") unless method

          h[klass] = method
        end
      end

      def start encoding = Nodes::Stream::UTF8
        @emitter.start_stream(encoding).tap do
          @started = true
        end
      end

      def finish
        @emitter.end_stream.tap do
          @finished = true
        end
      end

      def tree
        finish unless finished?
      end

      def push object
        start unless started?
        version = []
        version = [1,1] if @options[:header]

        case @options[:version]
        when Array
          version = @options[:version]
        when String
          version = @options[:version].split('.').map { |x| x.to_i }
        else
          version = [1,1]
        end if @options.key? :version

        @emitter.start_document version, [], false
        accept object
        @emitter.end_document
      end
      alias :<< :push

      def accept target
        # return any aliases we find
        if @st.key? target.object_id
          oid         = target.object_id
          node        = @st[oid]
          anchor      = oid.to_s
          node.anchor = anchor
          return @emitter.alias anchor
        end

        if target.respond_to?(:to_yaml)
          begin
            loc = target.method(:to_yaml).source_location.first
            if loc !~ /(syck\/rubytypes.rb|psych\/core_ext.rb)/
              unless target.respond_to?(:encode_with)
                if $VERBOSE
                  warn "implementing to_yaml is deprecated, please implement \"encode_with\""
                end

                target.to_yaml(:nodump => true)
              end
            end
          rescue
            # public_method or source_location might be overridden,
            # and it's OK to skip it since it's only to emit a warning
          end
        end

        if target.respond_to?(:encode_with)
          dump_coder target
        else
          send(@dispatch_cache[target.class], target)
        end
      end

      def visit_Psych_Omap o
        seq = @emitter.start_sequence(nil, '!omap', false, Nodes::Sequence::BLOCK)
        register(o, seq)

        o.each { |k,v| visit_Hash k => v }
        @emitter.end_sequence
      end

      def visit_Object o
        tag = Psych.dump_tags[o.class]
        unless tag
          klass = o.class == Object ? nil : o.class.name
          tag   = ['!ruby/object', klass].compact.join(':')
        end

        map = @emitter.start_mapping(nil, tag, false, Nodes::Mapping::BLOCK)
        register(o, map)

        dump_ivars o
        @emitter.end_mapping
      end

      def visit_Struct o
        tag = ['!ruby/struct', o.class.name].compact.join(':')

        register o, @emitter.start_mapping(nil, tag, false, Nodes::Mapping::BLOCK)
        o.members.each do |member|
          @emitter.scalar member.to_s, nil, nil, true, false, Nodes::Scalar::ANY
          accept o[member]
        end

        dump_ivars o

        @emitter.end_mapping
      end

      def visit_Exception o
        tag = ['!ruby/exception', o.class.name].join ':'

        @emitter.start_mapping nil, tag, false, Nodes::Mapping::BLOCK

        {
          'message'   => private_iv_get(o, 'mesg'),
          'backtrace' => private_iv_get(o, 'backtrace'),
        }.each do |k,v|
          next unless v
          @emitter.scalar k, nil, nil, true, false, Nodes::Scalar::ANY
          accept v
        end

        dump_ivars o

        @emitter.end_mapping
      end

      def visit_Regexp o
        register o, @emitter.scalar(o.inspect, nil, '!ruby/regexp', false, false, Nodes::Scalar::ANY)
      end

      def visit_DateTime o
        formatted = format_time o.to_time
        tag = '!ruby/object:DateTime'
        register o, @emitter.scalar(formatted, nil, tag, false, false, Nodes::Scalar::ANY)
      end

      def visit_Time o
        formatted = format_time o
        @emitter.scalar formatted, nil, nil, true, false, Nodes::Scalar::ANY
      end

      def visit_Rational o
        register o, @emitter.start_mapping(nil, '!ruby/object:Rational', false, Nodes::Mapping::BLOCK)

        [
          'denominator', o.denominator.to_s,
          'numerator', o.numerator.to_s
        ].each do |m|
          @emitter.scalar m, nil, nil, true, false, Nodes::Scalar::ANY
        end

        @emitter.end_mapping
      end

      def visit_Complex o
        register o, @emitter.start_mapping(nil, '!ruby/object:Complex', false, Nodes::Mapping::BLOCK)

        ['real', o.real.to_s, 'image', o.imag.to_s].each do |m|
          @emitter.scalar m, nil, nil, true, false, Nodes::Scalar::ANY
        end

        @emitter.end_mapping
      end

      def visit_Integer o
        @emitter.scalar o.to_s, nil, nil, true, false, Nodes::Scalar::ANY
      end
      alias :visit_TrueClass :visit_Integer
      alias :visit_FalseClass :visit_Integer
      alias :visit_Date :visit_Integer

      def visit_Float o
        if o.nan?
          @emitter.scalar '.nan', nil, nil, true, false, Nodes::Scalar::ANY
        elsif o.infinite?
          @emitter.scalar((o.infinite? > 0 ? '.inf' : '-.inf'),
            nil, nil, true, false, Nodes::Scalar::ANY)
        else
          @emitter.scalar o.to_s, nil, nil, true, false, Nodes::Scalar::ANY
        end
      end

      def visit_BigDecimal o
        @emitter.scalar o._dump, nil, '!ruby/object:BigDecimal', false, false, Nodes::Scalar::ANY
      end

      def binary? string
        string.encoding == Encoding::ASCII_8BIT ||
          string.index("\x00") ||
          string.count("\x00-\x7F", "^ -~\t\r\n").fdiv(string.length) > 0.3
      end
      private :binary?

      def visit_String o
        plain = false
        quote = false
        style = Nodes::Scalar::ANY

        if binary?(o)
          str   = [o].pack('m').chomp
          tag   = '!binary' # FIXME: change to below when syck is removed
          #tag   = 'tag:yaml.org,2002:binary'
          style = Nodes::Scalar::LITERAL
        else
          str   = o
          tag   = nil
          quote = !(String === @ss.tokenize(o))
          plain = !quote
        end

        ivars = find_ivars o

        if ivars.empty?
          unless o.class == ::String
            tag = "!ruby/string:#{o.class}"
          end
          @emitter.scalar str, nil, tag, plain, quote, style
        else
          maptag = '!ruby/string'
          maptag << ":#{o.class}" unless o.class == ::String

          @emitter.start_mapping nil, maptag, false, Nodes::Mapping::BLOCK
          @emitter.scalar 'str', nil, nil, true, false, Nodes::Scalar::ANY
          @emitter.scalar str, nil, tag, plain, quote, style

          dump_ivars o

          @emitter.end_mapping
        end
      end

      def visit_Module o
        raise TypeError, "can't dump anonymous module: #{o}" unless o.name
        register o, @emitter.scalar(o.name, nil, '!ruby/module', false, false, Nodes::Scalar::SINGLE_QUOTED)
      end

      def visit_Class o
        raise TypeError, "can't dump anonymous class: #{o}" unless o.name
        register o, @emitter.scalar(o.name, nil, '!ruby/class', false, false, Nodes::Scalar::SINGLE_QUOTED)
      end

      def visit_Range o
        register o, @emitter.start_mapping(nil, '!ruby/range', false, Nodes::Mapping::BLOCK)
        ['begin', o.begin, 'end', o.end, 'excl', o.exclude_end?].each do |m|
          accept m
        end
        @emitter.end_mapping
      end

      def visit_Hash o
        tag      = o.class == ::Hash ? nil : "!ruby/hash:#{o.class}"
        implicit = !tag

        register(o, @emitter.start_mapping(nil, tag, implicit, Psych::Nodes::Mapping::BLOCK))

        o.each do |k,v|
          accept k
          accept v
        end

        @emitter.end_mapping
      end

      def visit_Psych_Set o
        register(o, @emitter.start_mapping(nil, '!set', false, Psych::Nodes::Mapping::BLOCK))

        o.each do |k,v|
          accept k
          accept v
        end

        @emitter.end_mapping
      end

      def visit_Array o
        if o.class == ::Array
          register o, @emitter.start_sequence(nil, nil, true, Nodes::Sequence::BLOCK)
          o.each { |c| accept c }
          @emitter.end_sequence
        else
          visit_array_subclass o
        end
      end

      def visit_NilClass o
        @emitter.scalar('', nil, 'tag:yaml.org,2002:null', true, false, Nodes::Scalar::ANY)
      end

      def visit_Symbol o
        @emitter.scalar ":#{o}", nil, nil, true, false, Nodes::Scalar::ANY
      end

      private
      def visit_array_subclass o
        tag = "!ruby/array:#{o.class}"
        if o.instance_variables.empty?
          node = @emitter.start_sequence(nil, tag, false, Nodes::Sequence::BLOCK)
          register o, node
          o.each { |c| accept c }
          @emitter.end_sequence
        else
          node = @emitter.start_mapping(nil, tag, false, Nodes::Sequence::BLOCK)
          register o, node

          # Dump the internal list
          accept 'internal'
          @emitter.start_sequence(nil, nil, true, Nodes::Sequence::BLOCK)
          o.each { |c| accept c }
          @emitter.end_sequence

          # Dump the ivars
          accept 'ivars'
          @emitter.start_mapping(nil, nil, true, Nodes::Sequence::BLOCK)
          o.instance_variables.each do |ivar|
            accept ivar
            accept o.instance_variable_get ivar
          end
          @emitter.end_mapping

          @emitter.end_mapping
        end
      end

      def dump_list o
      end

      # '%:z' was no defined until 1.9.3
      if RUBY_VERSION < '1.9.3'
        def format_time time
          formatted = time.strftime("%Y-%m-%d %H:%M:%S.%9N")

          if time.utc?
            formatted += " Z"
          else
            zone = time.strftime('%z')
            formatted += " #{zone[0,3]}:#{zone[3,5]}"
          end

          formatted
        end
      else
        def format_time time
          if time.utc?
            time.strftime("%Y-%m-%d %H:%M:%S.%9N Z")
          else
            time.strftime("%Y-%m-%d %H:%M:%S.%9N %:z")
          end
        end
      end

      # FIXME: remove this method once "to_yaml_properties" is removed
      def find_ivars target
        begin
          loc = target.method(:to_yaml_properties).source_location.first
          unless loc.start_with?(Psych::DEPRECATED) || loc.end_with?('rubytypes.rb')
            if $VERBOSE
              warn "#{loc}: to_yaml_properties is deprecated, please implement \"encode_with(coder)\""
            end
            return target.to_yaml_properties
          end
        rescue
          # public_method or source_location might be overridden,
          # and it's OK to skip it since it's only to emit a warning.
        end

        target.instance_variables
      end

      def register target, yaml_obj
        @st[target.object_id] = yaml_obj
        yaml_obj
      end

      def dump_coder o
        tag = Psych.dump_tags[o.class]
        unless tag
          klass = o.class == Object ? nil : o.class.name
          tag   = ['!ruby/object', klass].compact.join(':')
        end

        c = Psych::Coder.new(tag)
        o.encode_with(c)
        emit_coder c
      end

      def emit_coder c
        case c.type
        when :scalar
          @emitter.scalar c.scalar, nil, c.tag, c.tag.nil?, false, Nodes::Scalar::ANY
        when :seq
          @emitter.start_sequence nil, c.tag, c.tag.nil?, Nodes::Sequence::BLOCK
          c.seq.each do |thing|
            accept thing
          end
          @emitter.end_sequence
        when :map
          @emitter.start_mapping nil, c.tag, c.implicit, c.style
          c.map.each do |k,v|
            @emitter.scalar k, nil, nil, true, false, Nodes::Scalar::ANY
            accept v
          end
          @emitter.end_mapping
        when :object
          accept c.object
        end
      end

      def dump_ivars target
        ivars = find_ivars target

        ivars.each do |iv|
          @emitter.scalar("#{iv.to_s.sub(/^@/, '')}", nil, nil, true, false, Nodes::Scalar::ANY)
          accept target.instance_variable_get(iv)
        end
      end
    end
  end
end

module Psych
  module Visitors
    class Emitter < Psych::Visitors::Visitor
      def initialize io, options = {}
        @handler = Psych::Emitter.new io
        @handler.indentation = options[:indentation] if options[:indentation]
        @handler.canonical = options[:canonical] if options[:canonical]
        @handler.line_width = options[:line_width] if options[:line_width]
      end

      def visit_Psych_Nodes_Stream o
        @handler.start_stream o.encoding
        o.children.each { |c| accept c }
        @handler.end_stream
      end

      def visit_Psych_Nodes_Document o
        @handler.start_document o.version, o.tag_directives, o.implicit
        o.children.each { |c| accept c }
        @handler.end_document o.implicit_end
      end

      def visit_Psych_Nodes_Scalar o
        @handler.scalar o.value, o.anchor, o.tag, o.plain, o.quoted, o.style
      end

      def visit_Psych_Nodes_Sequence o
        @handler.start_sequence o.anchor, o.tag, o.implicit, o.style
        o.children.each { |c| accept c }
        @handler.end_sequence
      end

      def visit_Psych_Nodes_Mapping o
        @handler.start_mapping o.anchor, o.tag, o.implicit, o.style
        o.children.each { |c| accept c }
        @handler.end_mapping
      end

      def visit_Psych_Nodes_Alias o
        @handler.alias o.anchor
      end
    end
  end
end

require 'strscan'

module Psych
  ###
  # Scan scalars for built in types
  class ScalarScanner
    # Taken from http://yaml.org/type/timestamp.html
    TIME = /^\d{4}-\d{1,2}-\d{1,2}([Tt]|\s+)\d{1,2}:\d\d:\d\d(\.\d*)?(\s*Z|[-+]\d{1,2}(:\d\d)?)?/

    # Taken from http://yaml.org/type/float.html
    FLOAT = /^(?:[-+]?([0-9][0-9_,]*)?\.[0-9.]*([eE][-+][0-9]+)?(?# base 10)
              |[-+]?[0-9][0-9_,]*(:[0-5]?[0-9])+\.[0-9_]*(?# base 60)
              |[-+]?\.(inf|Inf|INF)(?# infinity)
              |\.(nan|NaN|NAN)(?# not a number))$/x

    # Create a new scanner
    def initialize
      @string_cache = {}
    end

    # Tokenize +string+ returning the ruby object
    def tokenize string
      return nil if string.empty?
      return string if @string_cache.key?(string)

      case string
      when /^[A-Za-z~]/
        if string.length > 5
          @string_cache[string] = true
          return string
        end

        case string
        when /^[^ytonf~]/i
          @string_cache[string] = true
          string
        when '~', /^null$/i
          nil
        when /^(yes|true|on)$/i
          true
        when /^(no|false|off)$/i
          false
        else
          @string_cache[string] = true
          string
        end
      when TIME
        parse_time string
      when /^\d{4}-(?:1[012]|0\d|\d)-(?:[12]\d|3[01]|0\d|\d)$/
        require 'date'
        begin
          Date.strptime(string, '%Y-%m-%d')
        rescue ArgumentError
          string
        end
      when /^\.inf$/i
        1 / 0.0
      when /^-\.inf$/i
        -1 / 0.0
      when /^\.nan$/i
        0.0 / 0.0
      when /^:./
        if string =~ /^:(["'])(.*)\1/
          $2.sub(/^:/, '').to_sym
        else
          string.sub(/^:/, '').to_sym
        end
      when /^[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+$/
        i = 0
        string.split(':').each_with_index do |n,e|
          i += (n.to_i * 60 ** (e - 2).abs)
        end
        i
      when /^[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+\.[0-9_]*$/
        i = 0
        string.split(':').each_with_index do |n,e|
          i += (n.to_f * 60 ** (e - 2).abs)
        end
        i
      when FLOAT
        begin
          return Float(string.gsub(/[,_]/, ''))
        rescue ArgumentError
        end

        @string_cache[string] = true
        string
      else
        if string.count('.') < 2
          begin
            return Integer(string.gsub(/[,_]/, ''))
          rescue ArgumentError
          end
        end

        @string_cache[string] = true
        string
      end
    end

    ###
    # Parse and return a Time from +string+
    def parse_time string
      date, time = *(string.split(/[ tT]/, 2))
      (yy, m, dd) = date.split('-').map { |x| x.to_i }
      md = time.match(/(\d+:\d+:\d+)(?:\.(\d*))?\s*(Z|[-+]\d+(:\d\d)?)?/)

      (hh, mm, ss) = md[1].split(':').map { |x| x.to_i }
      us = (md[2] ? Rational("0.#{md[2]}") : 0) * 1000000

      time = Time.utc(yy, m, dd, hh, mm, ss, us)

      return time if 'Z' == md[3]
      return Time.at(time.to_i, us) unless md[3]

      tz = md[3].match(/^([+\-]?\d{1,2})\:?(\d{1,2})?$/)[1..-1].compact.map { |digit| Integer(digit, 10) }
      offset = tz.first * 3600

      if offset < 0
        offset -= ((tz[1] || 0) * 60)
      else
        offset += ((tz[1] || 0) * 60)
      end

      Time.at((time - offset).to_i, us)
    end
  end
end

require 'psych/scalar_scanner'

unless defined?(Regexp::NOENCODING)
  Regexp::NOENCODING = 32
end

module Psych
  module Visitors
    ###
    # This class walks a YAML AST, converting each node to ruby
    class ToRuby < Psych::Visitors::Visitor
      def initialize ss = ScalarScanner.new
        super()
        @st = {}
        @ss = ss
        @domain_types = Psych.domain_types
      end

      def accept target
        result = super
        return result if @domain_types.empty? || !target.tag

        key = target.tag.sub(/^[!\/]*/, '').sub(/(,\d+)\//, '\1:')
        key = "tag:#{key}" unless key =~ /^(tag:|x-private)/

        if @domain_types.key? key
          value, block = @domain_types[key]
          return block.call value, result
        end

        result
      end

      def deserialize o
        if klass = Psych.load_tags[o.tag]
          instance = klass.allocate

          if instance.respond_to?(:init_with)
            coder = Psych::Coder.new(o.tag)
            coder.scalar = o.value
            instance.init_with coder
          end

          return instance
        end

        return o.value if o.quoted
        return @ss.tokenize(o.value) unless o.tag

        case o.tag
        when '!binary', 'tag:yaml.org,2002:binary'
          o.value.unpack('m').first
        when /^!(?:str|ruby\/string)(?::(.*))?/, 'tag:yaml.org,2002:str'
          klass = resolve_class($1)
          if klass
            klass.allocate.replace o.value
          else
            o.value
          end
        when '!ruby/object:BigDecimal'
          require 'bigdecimal'
          BigDecimal._load o.value
        when "!ruby/object:DateTime"
          require 'date'
          @ss.parse_time(o.value).to_datetime
        when "!ruby/object:Complex"
          Complex(o.value)
        when "!ruby/object:Rational"
          Rational(o.value)
        when "!ruby/class", "!ruby/module"
          resolve_class o.value
        when "tag:yaml.org,2002:float", "!float"
          Float(@ss.tokenize(o.value))
        when "!ruby/regexp"
          o.value =~ /^\/(.*)\/([mixn]*)$/
          source  = $1
          options = 0
          lang    = nil
          ($2 || '').split('').each do |option|
            case option
            when 'x' then options |= Regexp::EXTENDED
            when 'i' then options |= Regexp::IGNORECASE
            when 'm' then options |= Regexp::MULTILINE
            when 'n' then options |= Regexp::NOENCODING
            else lang = option
            end
          end
          Regexp.new(*[source, options, lang].compact)
        when "!ruby/range"
          args = o.value.split(/([.]{2,3})/, 2).map { |s|
            accept Nodes::Scalar.new(s)
          }
          args.push(args.delete_at(1) == '...')
          Range.new(*args)
        when /^!ruby\/sym(bol)?:?(.*)?$/
          o.value.to_sym
        else
          @ss.tokenize o.value
        end
      end
      private :deserialize

      def visit_Psych_Nodes_Scalar o
        register o, deserialize(o)
      end

      def visit_Psych_Nodes_Sequence o
        if klass = Psych.load_tags[o.tag]
          instance = klass.allocate

          if instance.respond_to?(:init_with)
            coder = Psych::Coder.new(o.tag)
            coder.seq = o.children.map { |c| accept c }
            instance.init_with coder
          end

          return instance
        end

        case o.tag
        when '!omap', 'tag:yaml.org,2002:omap'
          map = register(o, Psych::Omap.new)
          o.children.each { |a|
            map[accept(a.children.first)] = accept a.children.last
          }
          map
        when /^!(?:seq|ruby\/array):(.*)$/
          klass = resolve_class($1)
          list  = register(o, klass.allocate)
          o.children.each { |c| list.push accept c }
          list
        else
          list = register(o, [])
          o.children.each { |c| list.push accept c }
          list
        end
      end

      def visit_Psych_Nodes_Mapping o
        return revive(Psych.load_tags[o.tag], o) if Psych.load_tags[o.tag]
        return revive_hash({}, o) unless o.tag

        case o.tag
        when /^!(?:str|ruby\/string)(?::(.*))?/, 'tag:yaml.org,2002:str'
          klass = resolve_class($1)
          members = Hash[*o.children.map { |c| accept c }]
          string = members.delete 'str'

          if klass
            string = klass.allocate
            string.replace string
          end

          init_with(string, members.map { |k,v| [k.to_s.sub(/^@/, ''),v] }, o)
        when /^!ruby\/array:(.*)$/
          klass = resolve_class($1)
          list  = register(o, klass.allocate)

          members = Hash[o.children.map { |c| accept c }.each_slice(2).to_a]
          list.replace members['internal']

          members['ivars'].each do |ivar, v|
            list.instance_variable_set ivar, v
          end
          list
        when /^!ruby\/struct:?(.*)?$/
          klass = resolve_class($1)

          if klass
            s = register(o, klass.allocate)

            members = {}
            struct_members = s.members.map { |x| x.to_sym }
            o.children.each_slice(2) do |k,v|
              member = accept(k)
              value  = accept(v)
              if struct_members.include?(member.to_sym)
                s.send("#{member}=", value)
              else
                members[member.to_s.sub(/^@/, '')] = value
              end
            end
            init_with(s, members, o)
          else
            members = o.children.map { |c| accept c }
            h = Hash[*members]
            Struct.new(*h.map { |k,v| k.to_sym }).new(*h.map { |k,v| v })
          end

        when '!ruby/range'
          h = Hash[*o.children.map { |c| accept c }]
          register o, Range.new(h['begin'], h['end'], h['excl'])

        when /^!ruby\/exception:?(.*)?$/
          h = Hash[*o.children.map { |c| accept c }]

          e = build_exception((resolve_class($1) || Exception),
                              h.delete('message'))
          init_with(e, h, o)

        when '!set', 'tag:yaml.org,2002:set'
          set = Psych::Set.new
          @st[o.anchor] = set if o.anchor
          o.children.each_slice(2) do |k,v|
            set[accept(k)] = accept(v)
          end
          set

        when '!ruby/object:Complex'
          h = Hash[*o.children.map { |c| accept c }]
          register o, Complex(h['real'], h['image'])

        when '!ruby/object:Rational'
          h = Hash[*o.children.map { |c| accept c }]
          register o, Rational(h['numerator'], h['denominator'])

        when /^!ruby\/object:?(.*)?$/
          name = $1 || 'Object'
          obj = revive((resolve_class(name) || Object), o)
          obj

        when /^!map:(.*)$/, /^!ruby\/hash:(.*)$/
          revive_hash resolve_class($1).new, o

        else
          revive_hash({}, o)
        end
      end

      def visit_Psych_Nodes_Document o
        accept o.root
      end

      def visit_Psych_Nodes_Stream o
        o.children.map { |c| accept c }
      end

      def visit_Psych_Nodes_Alias o
        @st.fetch(o.anchor) { raise BadAlias, "Unknown alias: #{o.anchor}" }
      end

      private
      def register node, object
        @st[node.anchor] = object if node.anchor
        object
      end

      def revive_hash hash, o
        @st[o.anchor] = hash if o.anchor

          o.children.each_slice(2) { |k,v|
          key = accept(k)

          if key == '<<'
            case v
            when Nodes::Alias
              hash.merge! accept(v)
            when Nodes::Sequence
              accept(v).reverse_each do |value|
                hash.merge! value
              end
            else
              hash[key] = accept(v)
            end
          else
            hash[key] = accept(v)
          end

        }
        hash
      end

      def revive klass, node
        s = klass.allocate
        @st[node.anchor] = s if node.anchor
        h = Hash[*node.children.map { |c| accept c }]
        init_with(s, h, node)
      end

      def init_with o, h, node
        c = Psych::Coder.new(node.tag)
        c.map = h

        if o.respond_to?(:init_with)
          o.init_with c
        elsif o.respond_to?(:yaml_initialize)
          if $VERBOSE
            warn "Implementing #{o.class}#yaml_initialize is deprecated, please implement \"init_with(coder)\""
          end
          o.yaml_initialize c.tag, c.map
        else
          h.each { |k,v| o.instance_variable_set(:"@#{k}", v) }
        end
        o
      end

      # Convert +klassname+ to a Class
      def resolve_class klassname
        return nil unless klassname and not klassname.empty?

        name    = klassname
        retried = false

        begin
          path2class(name)
        rescue ArgumentError, NameError => ex
          unless retried
            name    = "Struct::#{name}"
            retried = ex
            retry
          end
          raise retried
        end
      end
    end
  end
end

module Psych
  module Visitors
    class Visitor
      def accept target
        visit target
      end

      private

      DISPATCH = Hash.new do |hash, klass|
        hash[klass] = "visit_#{klass.name.gsub('::', '_')}"
      end

      def visit target
        send DISPATCH[target.class], target
      end
    end
  end
end

require 'psych/visitors/visitor'
require 'psych/visitors/to_ruby'
require 'psych/visitors/emitter'
require 'psych/visitors/yaml_tree'
require 'psych/visitors/json_tree'
require 'psych/visitors/depth_first'

module Psych
  module Streaming
    ###
    # Create a new streaming emitter.  Emitter will print to +io+.  See
    # Psych::Stream for an example.
    def initialize io
      super({}, self.class.const_get(:Emitter).new(io))
    end

    ###
    # Start streaming using +encoding+
    def start encoding = Nodes::Stream::UTF8
      super.tap { yield self if block_given?  }
    ensure
      finish if block_given?
    end

    private
    def register target, obj
    end
  end
end

module Psych
  module Nodes
    ###
    # This class represents a {YAML Alias}[http://yaml.org/spec/1.1/#alias].
    # It points to an +anchor+.
    #
    # A Psych::Nodes::Alias is a terminal node and may have no children.
    class Alias < Psych::Nodes::Node
      # The anchor this alias links to
      attr_accessor :anchor

      # Create a new Alias that points to an +anchor+
      def initialize anchor
        @anchor = anchor
      end
    end
  end
end

module Psych
  module Nodes
    ###
    # This class represents a {YAML Mapping}[http://yaml.org/spec/1.1/#mapping].
    #
    # A Psych::Nodes::Mapping node may have 0 or more children, but must have
    # an even number of children.  Here are the valid children a
    # Psych::Nodes::Mapping node may have:
    #
    # * Psych::Nodes::Sequence
    # * Psych::Nodes::Mapping
    # * Psych::Nodes::Scalar
    # * Psych::Nodes::Alias
    class Mapping < Psych::Nodes::Node
      # Any Map Style
      ANY   = 0

      # Block Map Style
      BLOCK = 1

      # Flow Map Style
      FLOW  = 2

      # The optional anchor for this mapping
      attr_accessor :anchor

      # The optional tag for this mapping
      attr_accessor :tag

      # Is this an implicit mapping?
      attr_accessor :implicit

      # The style of this mapping
      attr_accessor :style

      ###
      # Create a new Psych::Nodes::Mapping object.
      #
      # +anchor+ is the anchor associated with the map or +nil+.
      # +tag+ is the tag associated with the map or +nil+.
      # +implicit+ is a boolean indicating whether or not the map was implicitly
      # started.
      # +style+ is an integer indicating the mapping style.
      #
      # == See Also
      # See also Psych::Handler#start_mapping
      def initialize anchor = nil, tag = nil, implicit = true, style = BLOCK
        super()
        @anchor   = anchor
        @tag      = tag
        @implicit = implicit
        @style    = style
      end
    end
  end
end

module Psych
  module Nodes
    ###
    # This class represents a {YAML Scalar}[http://yaml.org/spec/1.1/#id858081].
    #
    # This node type is a terminal node and should not have any children.
    class Scalar < Psych::Nodes::Node
      # Any style scalar, the emitter chooses
      ANY           = 0

      # Plain scalar style
      PLAIN         = 1

      # Single quoted style
      SINGLE_QUOTED = 2

      # Double quoted style
      DOUBLE_QUOTED = 3

      # Literal style
      LITERAL       = 4

      # Folded style
      FOLDED        = 5

      # The scalar value
      attr_accessor :value

      # The anchor value (if there is one)
      attr_accessor :anchor

      # The tag value (if there is one)
      attr_accessor :tag

      # Is this a plain scalar?
      attr_accessor :plain

      # Is this scalar quoted?
      attr_accessor :quoted

      # The style of this scalar
      attr_accessor :style

      ###
      # Create a new Psych::Nodes::Scalar object.
      #
      # +value+ is the string value of the scalar
      # +anchor+ is an associated anchor or nil
      # +tag+ is an associated tag or nil
      # +plain+ is a boolean value
      # +quoted+ is a boolean value
      # +style+ is an integer idicating the string style
      #
      # == See Also
      #
      # See also Psych::Handler#scalar
      def initialize value, anchor = nil, tag = nil, plain = true, quoted = false, style = ANY
        @value  = value
        @anchor = anchor
        @tag    = tag
        @plain  = plain
        @quoted = quoted
        @style  = style
      end
    end
  end
end

module Psych
  module Nodes
    ###
    # This class represents a
    # {YAML sequence}[http://yaml.org/spec/1.1/#sequence/syntax].
    #
    # A YAML sequence is basically a list, and looks like this:
    #
    #   %YAML 1.1
    #   ---
    #   - I am
    #   - a Sequence
    #
    # A YAML sequence may have an anchor like this:
    #
    #   %YAML 1.1
    #   ---
    #   &A [
    #     "This sequence",
    #     "has an anchor"
    #   ]
    #
    # A YAML sequence may also have a tag like this:
    #
    #   %YAML 1.1
    #   ---
    #   !!seq [
    #     "This sequence",
    #     "has a tag"
    #   ]
    #
    # This class represents a sequence in a YAML document.  A
    # Psych::Nodes::Sequence node may have 0 or more children.  Valid children
    # for this node are:
    #
    # * Psych::Nodes::Sequence
    # * Psych::Nodes::Mapping
    # * Psych::Nodes::Scalar
    # * Psych::Nodes::Alias
    class Sequence < Psych::Nodes::Node
      # Any Styles, emitter chooses
      ANY   = 0

      # Block style sequence
      BLOCK = 1

      # Flow style sequence
      FLOW  = 2

      # The anchor for this sequence (if any)
      attr_accessor :anchor

      # The tag name for this sequence (if any)
      attr_accessor :tag

      # Is this sequence started implicitly?
      attr_accessor :implicit

      # The sequece style used
      attr_accessor :style

      ###
      # Create a new object representing a YAML sequence.
      #
      # +anchor+ is the anchor associated with the sequence or nil.
      # +tag+ is the tag associated with the sequence or nil.
      # +implicit+ a boolean indicating whether or not the sequence was
      # implicitly started.
      # +style+ is an integer indicating the list style.
      #
      # See Psych::Handler#start_sequence
      def initialize anchor = nil, tag = nil, implicit = true, style = BLOCK
        super()
        @anchor   = anchor
        @tag      = tag
        @implicit = implicit
        @style    = style
      end
    end
  end
end

module Psych
  module Nodes
    ###
    # This represents a YAML Document.  This node must be a child of
    # Psych::Nodes::Stream.  A Psych::Nodes::Document must have one child,
    # and that child may be one of the following:
    #
    # * Psych::Nodes::Sequence
    # * Psych::Nodes::Mapping
    # * Psych::Nodes::Scalar
    class Document < Psych::Nodes::Node
      # The version of the YAML document
      attr_accessor :version

      # A list of tag directives for this document
      attr_accessor :tag_directives

      # Was this document implicitly created?
      attr_accessor :implicit

      # Is the end of the document implicit?
      attr_accessor :implicit_end

      ###
      # Create a new Psych::Nodes::Document object.
      #
      # +version+ is a list indicating the YAML version.
      # +tags_directives+ is a list of tag directive declarations
      # +implicit+ is a flag indicating whether the document will be implicitly
      # started.
      #
      # == Example:
      # This creates a YAML document object that represents a YAML 1.1 document
      # with one tag directive, and has an implicit start:
      #
      #   Psych::Nodes::Document.new(
      #     [1,1],
      #     [["!", "tag:tenderlovemaking.com,2009:"]],
      #     true
      #   )
      #
      # == See Also
      # See also Psych::Handler#start_document
      def initialize version = [], tag_directives = [], implicit = false
        super()
        @version        = version
        @tag_directives = tag_directives
        @implicit       = implicit
        @implicit_end   = true
      end

      ###
      # Returns the root node.  A Document may only have one root node:
      # http://yaml.org/spec/1.1/#id898031
      def root
        children.first
      end
    end
  end
end

module Psych
  module Nodes
    ###
    # Represents a YAML stream.  This is the root node for any YAML parse
    # tree.  This node must have one or more child nodes.  The only valid
    # child node for a Psych::Nodes::Stream node is Psych::Nodes::Document.
    class Stream < Psych::Nodes::Node

      # Encodings supported by Psych (and libyaml)

      # Any encoding
      ANY     = Psych::Parser::ANY

      # UTF-8 encoding
      UTF8    = Psych::Parser::UTF8

      # UTF-16LE encoding
      UTF16LE = Psych::Parser::UTF16LE

      # UTF-16BE encoding
      UTF16BE = Psych::Parser::UTF16BE

      # The encoding used for this stream
      attr_accessor :encoding

      ###
      # Create a new Psych::Nodes::Stream node with an +encoding+ that
      # defaults to Psych::Nodes::Stream::UTF8.
      #
      # See also Psych::Handler#start_stream
      def initialize encoding = UTF8
        super()
        @encoding = encoding
      end
    end
  end
end

require 'stringio'

module Psych
  module Nodes
    ###
    # The base class for any Node in a YAML parse tree.  This class should
    # never be instantiated.
    class Node
      include Enumerable

      # The children of this node
      attr_reader :children

      # An associated tag
      attr_reader :tag

      # Create a new Psych::Nodes::Node
      def initialize
        @children = []
      end

      ###
      # Iterate over each node in the tree. Yields each node to +block+ depth
      # first.
      def each &block
        return enum_for :each unless block_given?
        Visitors::DepthFirst.new(block).accept self
      end

      ###
      # Convert this node to Ruby.
      #
      # See also Psych::Visitors::ToRuby
      def to_ruby
        Visitors::ToRuby.new.accept self
      end
      alias :transform :to_ruby

      ###
      # Convert this node to YAML.
      #
      # See also Psych::Visitors::Emitter
      def yaml io = nil, options = {}
        real_io = io || StringIO.new(''.encode('utf-8'))

        Visitors::Emitter.new(real_io, options).accept self
        return real_io.string unless io
        io
      end
      alias :to_yaml :yaml
    end
  end
end

require 'psych/nodes/node'
require 'psych/nodes/stream'
require 'psych/nodes/document'
require 'psych/nodes/sequence'
require 'psych/nodes/scalar'
require 'psych/nodes/mapping'
require 'psych/nodes/alias'

module Psych
  ###
  # = Overview
  #
  # When using Psych.load to deserialize a YAML document, the document is
  # translated to an intermediary AST.  That intermediary AST is then
  # translated in to a Ruby object graph.
  #
  # In the opposite direction, when using Psych.dump, the Ruby object graph is
  # translated to an intermediary AST which is then converted to a YAML
  # document.
  #
  # Psych::Nodes contains all of the classes that make up the nodes of a YAML
  # AST.  You can manually build an AST and use one of the visitors (see
  # Psych::Visitors) to convert that AST to either a YAML document or to a
  # Ruby object graph.
  #
  # Here is an example of building an AST that represents a list with one
  # scalar:
  #
  #   # Create our nodes
  #   stream = Psych::Nodes::Stream.new
  #   doc    = Psych::Nodes::Document.new
  #   seq    = Psych::Nodes::Sequence.new
  #   scalar = Psych::Nodes::Scalar.new('foo')
  #
  #   # Build up our tree
  #   stream.children << doc
  #   doc.children    << seq
  #   seq.children    << scalar
  #
  # The stream is the root of the tree.  We can then convert the tree to YAML:
  #
  #   stream.to_yaml => "---\n- foo\n"
  #
  # Or convert it to Ruby:
  #
  #   stream.to_ruby => [["foo"]]
  #
  # == YAML AST Requirements
  #
  # A valid YAML AST *must* have one Psych::Nodes::Stream at the root.  A
  # Psych::Nodes::Stream node must have 1 or more Psych::Nodes::Document nodes
  # as children.
  #
  # Psych::Nodes::Document nodes must have one and *only* one child.  That child
  # may be one of:
  #
  # * Psych::Nodes::Sequence
  # * Psych::Nodes::Mapping
  # * Psych::Nodes::Scalar
  #
  # Psych::Nodes::Sequence and Psych::Nodes::Mapping nodes may have many
  # children, but Psych::Nodes::Mapping nodes should have an even number of
  # children.
  #
  # All of these are valid children for Psych::Nodes::Sequence and
  # Psych::Nodes::Mapping nodes:
  #
  # * Psych::Nodes::Sequence
  # * Psych::Nodes::Mapping
  # * Psych::Nodes::Scalar
  # * Psych::Nodes::Alias
  #
  # Psych::Nodes::Scalar and Psych::Nodes::Alias are both terminal nodes and
  # should not have any children.
  module Nodes
  end
end

require 'psych.so'
require 'psych/nodes'
require 'psych/streaming'
require 'psych/visitors'
require 'psych/handler'
require 'psych/tree_builder'
require 'psych/parser'
require 'psych/omap'
require 'psych/set'
require 'psych/coder'
require 'psych/core_ext'
require 'psych/deprecated'
require 'psych/stream'
require 'psych/json/tree_builder'
require 'psych/json/stream'
require 'psych/handlers/document_stream'

###
# = Overview
#
# Psych is a YAML parser and emitter.  Psych leverages
# libyaml[http://libyaml.org] for it's YAML parsing and emitting capabilities.
# In addition to wrapping libyaml, Psych also knows how to serialize and
# de-serialize most Ruby objects to and from the YAML format.
#
# = I NEED TO PARSE OR EMIT YAML RIGHT NOW!
#
#   # Parse some YAML
#   Psych.load("--- foo") # => "foo"
#
#   # Emit some YAML
#   Psych.dump("foo")     # => "--- foo\n...\n"
#   { :a => 'b'}.to_yaml  # => "---\n:a: b\n"
#
# Got more time on your hands?  Keep on reading!
#
# == YAML Parsing
#
# Psych provides a range of interfaces for parsing a YAML document ranging from
# low level to high level, depending on your parsing needs.  At the lowest
# level, is an event based parser.  Mid level is access to the raw YAML AST,
# and at the highest level is the ability to unmarshal YAML to ruby objects.
#
# === Low level parsing
#
# The lowest level parser should be used when the YAML input is already known,
# and the developer does not want to pay the price of building an AST or
# automatic detection and conversion to ruby objects.  See Psych::Parser for
# more information on using the event based parser.
#
# === Mid level parsing
#
# Psych provides access to an AST produced from parsing a YAML document.  This
# tree is built using the Psych::Parser and Psych::TreeBuilder.  The AST can
# be examined and manipulated freely.  Please see Psych::parse_stream,
# Psych::Nodes, and Psych::Nodes::Node for more information on dealing with
# YAML syntax trees.
#
# === High level parsing
#
# The high level YAML parser provided by Psych simply takes YAML as input and
# returns a Ruby data structure.  For information on using the high level parser
# see Psych.load
#
# == YAML Emitting
#
# Psych provides a range of interfaces ranging from low to high level for
# producing YAML documents.  Very similar to the YAML parsing interfaces, Psych
# provides at the lowest level, an event based system, mid-level is building
# a YAML AST, and the highest level is converting a Ruby object straight to
# a YAML document.
#
# === Low level emitting
#
# The lowest level emitter is an event based system.  Events are sent to a
# Psych::Emitter object.  That object knows how to convert the events to a YAML
# document.  This interface should be used when document format is known in
# advance or speed is a concern.  See Psych::Emitter for more information.
#
# === Mid level emitting
#
# At the mid level is building an AST.  This AST is exactly the same as the AST
# used when parsing a YAML document.  Users can build an AST by hand and the
# AST knows how to emit itself as a YAML document.  See Psych::Nodes,
# Psych::Nodes::Node, and Psych::TreeBuilder for more information on building
# a YAML AST.
#
# === High level emitting
#
# The high level emitter has the easiest interface.  Psych simply takes a Ruby
# data structure and converts it to a YAML document.  See Psych.dump for more
# information on dumping a Ruby data structure.

module Psych
  # The version is Psych you're using
  VERSION         = '1.3.2'

  # The version of libyaml Psych is using
  LIBYAML_VERSION = Psych.libyaml_version.join '.'

  class Exception < RuntimeError
  end

  class BadAlias < Exception
  end

  ###
  # Load +yaml+ in to a Ruby data structure.  If multiple documents are
  # provided, the object contained in the first document will be returned.
  # +filename+ will be used in the exception message if any exception is raised
  # while parsing.
  #
  # Raises a Psych::SyntaxError when a YAML syntax error is detected.
  #
  # Example:
  #
  #   Psych.load("--- a")             # => 'a'
  #   Psych.load("---\n - a\n - b")   # => ['a', 'b']
  #
  #   begin
  #     Psych.load("--- `", "file.txt")
  #   rescue Psych::SyntaxError => ex
  #     ex.file    # => 'file.txt'
  #     ex.message # => "(foo.txt): found character that cannot start any token"
  #   end
  def self.load yaml, filename = nil
    result = parse(yaml, filename)
    result ? result.to_ruby : result
  end

  ###
  # Parse a YAML string in +yaml+.  Returns the first object of a YAML AST.
  # +filename+ is used in the exception message if a Psych::SyntaxError is
  # raised.
  #
  # Raises a Psych::SyntaxError when a YAML syntax error is detected.
  #
  # Example:
  #
  #   Psych.parse("---\n - a\n - b") # => #<Psych::Nodes::Sequence:0x00>
  #
  #   begin
  #     Psych.parse("--- `", "file.txt")
  #   rescue Psych::SyntaxError => ex
  #     ex.file    # => 'file.txt'
  #     ex.message # => "(foo.txt): found character that cannot start any token"
  #   end
  #
  # See Psych::Nodes for more information about YAML AST.
  def self.parse yaml, filename = nil
    parse_stream(yaml, filename) do |node|
      return node
    end
    false
  end

  ###
  # Parse a file at +filename+. Returns the YAML AST.
  #
  # Raises a Psych::SyntaxError when a YAML syntax error is detected.
  def self.parse_file filename
    File.open filename, 'r:bom|utf-8' do |f|
      parse f, filename
    end
  end

  ###
  # Returns a default parser
  def self.parser
    Psych::Parser.new(TreeBuilder.new)
  end

  ###
  # Parse a YAML string in +yaml+.  Returns the full AST for the YAML document.
  # This method can handle multiple YAML documents contained in +yaml+.
  # +filename+ is used in the exception message if a Psych::SyntaxError is
  # raised.
  #
  # If a block is given, a Psych::Nodes::Document node will be yielded to the
  # block as it's being parsed.
  #
  # Raises a Psych::SyntaxError when a YAML syntax error is detected.
  #
  # Example:
  #
  #   Psych.parse_stream("---\n - a\n - b") # => #<Psych::Nodes::Stream:0x00>
  #
  #   Psych.parse_stream("--- a\n--- b") do |node|
  #     node # => #<Psych::Nodes::Document:0x00>
  #   end
  #
  #   begin
  #     Psych.parse_stream("--- `", "file.txt")
  #   rescue Psych::SyntaxError => ex
  #     ex.file    # => 'file.txt'
  #     ex.message # => "(foo.txt): found character that cannot start any token"
  #   end
  #
  # See Psych::Nodes for more information about YAML AST.
  def self.parse_stream yaml, filename = nil, &block
    if block_given?
      parser = Psych::Parser.new(Handlers::DocumentStream.new(&block))
      parser.parse yaml, filename
    else
      parser = self.parser
      parser.parse yaml, filename
      parser.handler.root
    end
  end

  ###
  # call-seq:
  #   Psych.dump(o)               -> string of yaml
  #   Psych.dump(o, options)      -> string of yaml
  #   Psych.dump(o, io)           -> io object passed in
  #   Psych.dump(o, io, options)  -> io object passed in
  #
  # Dump Ruby object +o+ to a YAML string.  Optional +options+ may be passed in
  # to control the output format.  If an IO object is passed in, the YAML will
  # be dumped to that IO object.
  #
  # Example:
  #
  #   # Dump an array, get back a YAML string
  #   Psych.dump(['a', 'b'])  # => "---\n- a\n- b\n"
  #
  #   # Dump an array to an IO object
  #   Psych.dump(['a', 'b'], StringIO.new)  # => #<StringIO:0x000001009d0890>
  #
  #   # Dump an array with indentation set
  #   Psych.dump(['a', ['b']], :indentation => 3) # => "---\n- a\n-  - b\n"
  #
  #   # Dump an array to an IO with indentation set
  #   Psych.dump(['a', ['b']], StringIO.new, :indentation => 3)
  def self.dump o, io = nil, options = {}
    if Hash === io
      options = io
      io      = nil
    end

    visitor = Psych::Visitors::YAMLTree.new options
    visitor << o
    visitor.tree.yaml io, options
  end

  ###
  # Dump a list of objects as separate documents to a document stream.
  #
  # Example:
  #
  #   Psych.dump_stream("foo\n  ", {}) # => "--- ! \"foo\\n  \"\n--- {}\n"
  def self.dump_stream *objects
    visitor = Psych::Visitors::YAMLTree.new {}
    objects.each do |o|
      visitor << o
    end
    visitor.tree.yaml
  end

  ###
  # Dump Ruby object +o+ to a JSON string.
  def self.to_json o
    visitor = Psych::Visitors::JSONTree.new
    visitor << o
    visitor.tree.yaml
  end

  ###
  # Load multiple documents given in +yaml+.  Returns the parsed documents
  # as a list.  If a block is given, each document will be converted to ruby
  # and passed to the block during parsing
  #
  # Example:
  #
  #   Psych.load_stream("--- foo\n...\n--- bar\n...") # => ['foo', 'bar']
  #
  #   list = []
  #   Psych.load_stream("--- foo\n...\n--- bar\n...") do |ruby|
  #     list << ruby
  #   end
  #   list # => ['foo', 'bar']
  #
  def self.load_stream yaml, filename = nil
    if block_given?
      parse_stream(yaml, filename) do |node|
        yield node.to_ruby
      end
    else
      parse_stream(yaml, filename).children.map { |child| child.to_ruby }
    end
  end

  ###
  # Load the document contained in +filename+.  Returns the yaml contained in
  # +filename+ as a ruby object
  def self.load_file filename
    File.open(filename, 'r:bom|utf-8') { |f| self.load f, filename }
  end

  # :stopdoc:
  @domain_types = {}
  def self.add_domain_type domain, type_tag, &block
    key = ['tag', domain, type_tag].join ':'
    @domain_types[key] = [key, block]
    @domain_types["tag:#{type_tag}"] = [key, block]
  end

  def self.add_builtin_type type_tag, &block
    domain = 'yaml.org,2002'
    key = ['tag', domain, type_tag].join ':'
    @domain_types[key] = [key, block]
  end

  def self.remove_type type_tag
    @domain_types.delete type_tag
  end

  @load_tags = {}
  @dump_tags = {}
  def self.add_tag tag, klass
    @load_tags[tag] = klass
    @dump_tags[klass] = tag
  end

  class << self
    attr_accessor :load_tags
    attr_accessor :dump_tags
    attr_accessor :domain_types
  end
  # :startdoc:
end

##
# The YAML module allows you to use one of the two YAML engines that ship with
# ruby.  By default Psych is used but the old and unmaintained Syck may be
# chosen.
#
# See Psych or Syck for usage and documentation.
#
# To set the YAML engine to syck:
#
#   YAML::ENGINE.yamler = 'syck'
#
# To set the YAML engine back to psych:
#
#   YAML::ENGINE.yamler = 'psych'

module YAML
  class EngineManager # :nodoc:
    attr_reader :yamler

    def initialize
      @yamler = nil
    end

    def syck?
      'syck' == @yamler
    end

    def yamler= engine
      raise(ArgumentError, "bad engine") unless %w{syck psych}.include?(engine)

      require engine unless (engine == 'syck' ? Syck : Psych).const_defined?(:VERSION)

      Object.class_eval <<-eorb, __FILE__, __LINE__ + 1
        remove_const 'YAML'
        YAML = #{engine.capitalize}
        remove_method :to_yaml
        alias :to_yaml :#{engine}_to_yaml
      eorb

      @yamler = engine
      engine
    end
  end

  ##
  # Allows changing the current YAML engine.  See YAML for details.

  ENGINE = YAML::EngineManager.new
end

if defined?(Psych)
  engine = 'psych'
elsif defined?(Syck)
  engine = 'syck'
else
  begin
    require 'psych'
    engine = 'psych'
  rescue LoadError
    warn "#{caller[0]}:"
    warn "It seems your ruby installation is missing psych (for YAML output)."
    warn "To eliminate this warning, please install libyaml and reinstall your ruby."
    require 'syck'
    engine = 'syck'
  end
end

module Syck
  ENGINE = YAML::ENGINE
end

module Psych
  ENGINE = YAML::ENGINE
end

YAML::ENGINE.yamler = engine

require 'yaml'
require 'gherkin/rubify'
require 'gherkin/native'

module Gherkin
  class I18n
    LexerNotFound = Class.new(LoadError)

    native_impl('gherkin') unless defined?(BYPASS_NATIVE_IMPL)

    FEATURE_ELEMENT_KEYS = %w{feature background scenario scenario_outline examples}
    STEP_KEYWORD_KEYS    = %w{given when then and but}
    KEYWORD_KEYS         = FEATURE_ELEMENT_KEYS + STEP_KEYWORD_KEYS
    LANGUAGES            = YAML.load_file(File.dirname(__FILE__) + '/i18n.yml')

    class << self
      include Rubify

      # Used by code generators for other lexer tools like pygments lexer and textmate bundle
      def all
        LANGUAGES.keys.sort.map{|iso_code| get(iso_code)}
      end

      def get(iso_code)
        languages[iso_code] ||= new(iso_code)
      end

      # Returns all keyword translations and aliases of +keywords+, escaped and joined with <tt>|</tt>.
      # This method is convenient for editor support and syntax highlighting engines for Gherkin, where
      # there is typically a code generation tool to generate regular expressions for recognising the
      # various I18n translations of Gherkin's keywords.
      #
      # The +keywords+ arguments can be one of <tt>:feature</tt>, <tt>:background</tt>, <tt>:scenario</tt>, 
      # <tt>:scenario_outline</tt>, <tt>:examples</tt>, <tt>:step</tt>.
      def keyword_regexp(*keywords)
        unique_keywords = all.map do |i18n|
          keywords.map do |keyword|
            if keyword.to_s == 'step'
              i18n.step_keywords.to_a
            else
              i18n.keywords(keyword).to_a
            end
          end
        end
        
        unique_keywords.flatten.compact.map{|kw| kw.to_s}.sort.reverse.uniq.join('|').gsub(/\*/, '\*')
      end

      def code_keywords
        rubify(all.map{|i18n| i18n.code_keywords}).flatten.uniq.sort
      end

      def code_keyword_for(gherkin_keyword)
        gherkin_keyword.gsub(/[\s',!]/, '').strip
      end

      def language_table
        require 'stringio'
        require 'gherkin/formatter/pretty_formatter'
        require 'gherkin/formatter/model'
        io = StringIO.new
        pf = Gherkin::Formatter::PrettyFormatter.new(io, true, false)
        table = all.map do |i18n|
          Formatter::Model::DataTableRow.new([], [i18n.iso_code, i18n.keywords('name')[0], i18n.keywords('native')[0]], nil)
        end
        pf.table(table)
        io.string
      end

      def unicode_escape(word, prefix="\\u")
        word = word.unpack("U*").map do |c|
          if c > 127 || c == 32
            "#{prefix}%04x" % c
          else
            c.chr
          end
        end.join
      end

      private

      def languages
        @languages ||= {}
      end
    end

    attr_reader :iso_code

    def initialize(iso_code)
      @iso_code = iso_code
      @keywords = LANGUAGES[iso_code]
      raise "Language not supported: #{iso_code.inspect}" if @iso_code.nil?
      @keywords['grammar_name'] = @keywords['name'].gsub(/\s/, '')
    end

    def lexer(listener, force_ruby=false)
      if force_ruby
        rb(listener)
      else
        begin
          c(listener)
        rescue NameError, LoadError => e
          warn("WARNING: #{e.message}. Reverting to Ruby lexer.")
          rb(listener)
        end
      end
    rescue LoadError => e
      raise LexerNotFound, "No lexer was found for #{iso_code} (#{e.message}). Supported languages are listed in gherkin/i18n.yml."
    end

    def c(listener)
      require 'gherkin/c_lexer'
      CLexer[underscored_iso_code].new(listener)
    end

    def rb(listener)
      require 'gherkin/rb_lexer'
      RbLexer[underscored_iso_code].new(listener)
    end

    def js(listener)
      require 'gherkin/js_lexer'
      JsLexer[underscored_iso_code].new(listener)
    end

    def underscored_iso_code
      @iso_code.gsub(/[\s-]/, '_').downcase
    end

    # Keywords that can be used in Gherkin source
    def step_keywords
      STEP_KEYWORD_KEYS.map{|iso_code| keywords(iso_code)}.flatten.uniq
    end

    # Keywords that can be used in code
    def code_keywords
      result = step_keywords.map{|keyword| self.class.code_keyword_for(keyword)}
      result.delete('*')
      result
    end

    def keywords(key)
      key = key.to_s
      raise "No #{key.inspect} in #{@keywords.inspect}" if @keywords[key].nil?
      @keywords[key].split('|').map{|keyword| real_keyword(key, keyword)}
    end

    def keyword_table
      require 'stringio'
      require 'gherkin/formatter/pretty_formatter'
      require 'gherkin/formatter/model'
      io = StringIO.new
      pf = Gherkin::Formatter::PrettyFormatter.new(io, false, false)

      gherkin_keyword_table = KEYWORD_KEYS.map do |key|
        Formatter::Model::Row.new([], [key, keywords(key).map{|keyword| %{"#{keyword}"}}.join(', ')], nil)
      end
      
      code_keyword_table = STEP_KEYWORD_KEYS.map do |key|
        code_keywords = keywords(key).reject{|keyword| keyword == '* '}.map do |keyword|
          %{"#{self.class.code_keyword_for(keyword)}"}
        end.join(', ')
        Formatter::Model::Row.new([], ["#{key} (code)", code_keywords], nil)
      end
      
      pf.table(gherkin_keyword_table + code_keyword_table)
      io.string
    end

    private

    def real_keyword(key, keyword)
      if(STEP_KEYWORD_KEYS.index(key))
        (keyword + ' ').sub(/< $/, '')
      else
        keyword
      end
    end
  end
end

require 'gherkin/i18n'
require 'gherkin/native'

module Gherkin
  module Lexer
    LexingError = Class.new(StandardError)

    # The main entry point to lexing Gherkin source.
    class I18nLexer
      native_impl('gherkin')

      COMMENT_OR_EMPTY_LINE_PATTERN = /^\s*#|^\s*$/
      LANGUAGE_PATTERN = /^\s*#\s*language\s*:\s*([a-zA-Z\-]+)/ #:nodoc:
      attr_reader :i18n_language

      def initialize(listener, force_ruby=false)
        @listener = listener
        @force_ruby = force_ruby
      end

      def scan(source)
        create_delegate(source).scan(source)
      end

    private

      def create_delegate(source)
        @i18n_language = lang(source)
        @i18n_language.lexer(@listener, @force_ruby)
      end

      def lang(source)
        key = 'en'
        source.each_line do |line|
          break unless COMMENT_OR_EMPTY_LINE_PATTERN =~ line
          if LANGUAGE_PATTERN =~ line
            key = $1
            break
          end
        end
        I18n.get(key)
      end

    end
  end
end

require "rubygems/deprecate"

##
# Available list of platforms for targeting Gem installations.

class Gem::Platform

  @local = nil

  attr_accessor :cpu

  attr_accessor :os

  attr_accessor :version

  def self.local
    arch = Gem::ConfigMap[:arch]
    arch = "#{arch}_60" if arch =~ /mswin32$/
    @local ||= new(arch)
  end

  def self.match(platform)
    Gem.platforms.any? do |local_platform|
      platform.nil? or local_platform == platform or
        (local_platform != Gem::Platform::RUBY and local_platform =~ platform)
    end
  end

  def self.new(arch) # :nodoc:
    case arch
    when Gem::Platform::CURRENT then
      Gem::Platform.local
    when Gem::Platform::RUBY, nil, '' then
      Gem::Platform::RUBY
    else
      super
    end
  end

  def initialize(arch)
    case arch
    when Array then
      @cpu, @os, @version = arch
    when String then
      arch = arch.split '-'

      if arch.length > 2 and arch.last !~ /\d/ then # reassemble x86-linux-gnu
        extra = arch.pop
        arch.last << "-#{extra}"
      end

      cpu = arch.shift

      @cpu = case cpu
             when /i\d86/ then 'x86'
             else cpu
             end

      if arch.length == 2 and arch.last =~ /^\d+(\.\d+)?$/ then # for command-line
        @os, @version = arch
        return
      end

      os, = arch
      @cpu, os = nil, cpu if os.nil? # legacy jruby

      @os, @version = case os
                      when /aix(\d+)/ then             [ 'aix',       $1  ]
                      when /cygwin/ then               [ 'cygwin',    nil ]
                      when /darwin(\d+)?/ then         [ 'darwin',    $1  ]
                      when /^macruby$/ then            [ 'macruby',   nil ]
                      when /freebsd(\d+)/ then         [ 'freebsd',   $1  ]
                      when /hpux(\d+)/ then            [ 'hpux',      $1  ]
                      when /^java$/, /^jruby$/ then    [ 'java',      nil ]
                      when /^java([\d.]*)/ then        [ 'java',      $1  ]
                      when /^dotnet$/ then             [ 'dotnet',    nil ]
                      when /^dotnet([\d.]*)/ then      [ 'dotnet',    $1  ]
                      when /linux/ then                [ 'linux',     $1  ]
                      when /mingw32/ then              [ 'mingw32',   nil ]
                      when /(mswin\d+)(\_(\d+))?/ then
                        os, version = $1, $3
                        @cpu = 'x86' if @cpu.nil? and os =~ /32$/
                        [os, version]
                      when /netbsdelf/ then            [ 'netbsdelf', nil ]
                      when /openbsd(\d+\.\d+)/ then    [ 'openbsd',   $1  ]
                      when /solaris(\d+\.\d+)/ then    [ 'solaris',   $1  ]
                      # test
                      when /^(\w+_platform)(\d+)/ then [ $1,          $2  ]
                      else                             [ 'unknown',   nil ]
                      end
    when Gem::Platform then
      @cpu = arch.cpu
      @os = arch.os
      @version = arch.version
    else
      raise ArgumentError, "invalid argument #{arch.inspect}"
    end
  end

  def inspect
    "#<%s:0x%x @cpu=%p, @os=%p, @version=%p>" % [self.class, object_id, *to_a]
  end

  def to_a
    [@cpu, @os, @version]
  end

  def to_s
    to_a.compact.join '-'
  end

  def empty?
    to_s.empty?
  end

  ##
  # Is +other+ equal to this platform?  Two platforms are equal if they have
  # the same CPU, OS and version.

  def ==(other)
    self.class === other and to_a == other.to_a
  end

  alias :eql? :==

  def hash # :nodoc:
    to_a.hash
  end

  ##
  # Does +other+ match this platform?  Two platforms match if they have the
  # same CPU, or either has a CPU of 'universal', they have the same OS, and
  # they have the same version, or either has no version.

  def ===(other)
    return nil unless Gem::Platform === other

    # cpu
    (@cpu == 'universal' or other.cpu == 'universal' or @cpu == other.cpu) and

    # os
    @os == other.os and

    # version
    (@version.nil? or other.version.nil? or @version == other.version)
  end

  ##
  # Does +other+ match this platform?  If +other+ is a String it will be
  # converted to a Gem::Platform first.  See #=== for matching rules.

  def =~(other)
    case other
    when Gem::Platform then # nop
    when String then
      # This data is from http://gems.rubyforge.org/gems/yaml on 19 Aug 2007
      other = case other
              when /^i686-darwin(\d)/     then ['x86',       'darwin',  $1    ]
              when /^i\d86-linux/         then ['x86',       'linux',   nil   ]
              when 'java', 'jruby'        then [nil,         'java',    nil   ]
              when /dotnet(\-(\d+\.\d+))?/ then ['universal','dotnet',  $2    ]
              when /mswin32(\_(\d+))?/    then ['x86',       'mswin32', $2    ]
              when 'powerpc-darwin'       then ['powerpc',   'darwin',  nil   ]
              when /powerpc-darwin(\d)/   then ['powerpc',   'darwin',  $1    ]
              when /sparc-solaris2.8/     then ['sparc',     'solaris', '2.8' ]
              when /universal-darwin(\d)/ then ['universal', 'darwin',  $1    ]
              else                             other
              end

      other = Gem::Platform.new other
    else
      return nil
    end

    self === other
  end

  ##
  # A pure-ruby gem that may use Gem::Specification#extensions to build
  # binary files.

  RUBY = 'ruby'

  ##
  # A platform-specific gem that is built for the packaging ruby's platform.
  # This will be replaced with Gem::Platform::local.

  CURRENT = 'current'

  extend Gem::Deprecate

  deprecate :empty?, :none, 2011, 11
end


##
# Provides a single method +deprecate+ to be used to declare when
# something is going away.
#
#     class Legacy
#       def self.klass_method
#         # ...
#       end
#
#       def instance_method
#         # ...
#       end
#
#       extend Gem::Deprecate
#       deprecate :instance_method, "X.z", 2011, 4
#
#       class << self
#         extend Gem::Deprecate
#         deprecate :klass_method, :none, 2011, 4
#       end
#     end

module Gem
  module Deprecate

    def self.skip # :nodoc:
      @skip ||= false
    end

    def self.skip= v # :nodoc:
      @skip = v
    end

    ##
    # Temporarily turn off warnings. Intended for tests only.

    def skip_during
      Gem::Deprecate.skip, original = true, Gem::Deprecate.skip
      yield
    ensure
      Gem::Deprecate.skip = original
    end

    ##
    # Simple deprecation method that deprecates +name+ by wrapping it up
    # in a dummy method. It warns on each call to the dummy method
    # telling the user of +repl+ (unless +repl+ is :none) and the
    # year/month that it is planned to go away.

    def deprecate name, repl, year, month
      class_eval {
        old = "_deprecated_#{name}"
        alias_method old, name
        define_method name do |*args, &block| # TODO: really works on 1.8.7?
          klass = self.kind_of? Module
          target = klass ? "#{self}." : "#{self.class}#"
          msg = [ "NOTE: #{target}#{name} is deprecated",
            repl == :none ? " with no replacement" : ", use #{repl}",
            ". It will be removed on or after %4d-%02d-01." % [year, month],
            "\n#{target}#{name} called from #{Gem.location_of_caller.join(":")}",
          ]
          warn "#{msg.join}." unless Gem::Deprecate.skip
          send old, *args, &block
        end
      }
    end

    module_function :deprecate, :skip_during
  end
end

require "rubygems/version"

##
# A Requirement is a set of one or more version restrictions. It supports a
# few (<tt>=, !=, >, <, >=, <=, ~></tt>) different restriction operators.

# REFACTOR: The fact that a requirement is singular or plural is kind of
# awkward. Is Requirement the right name for this? Or should it be one
# [op, number] pair, and we call the list of requirements something else?
# Since a Requirement is held by a Dependency, maybe this should be made
# singular and the list aspect should be pulled up into Dependency?

require "rubygems/version"
require "rubygems/deprecate"

class Gem::Requirement
  include Comparable

  OPS = { #:nodoc:
    "="  =>  lambda { |v, r| v == r },
    "!=" =>  lambda { |v, r| v != r },
    ">"  =>  lambda { |v, r| v > r  },
    "<"  =>  lambda { |v, r| v < r  },
    ">=" =>  lambda { |v, r| v >= r },
    "<=" =>  lambda { |v, r| v <= r },
    "~>" =>  lambda { |v, r| v >= r && v.release < r.bump }
  }

  quoted  = OPS.keys.map { |k| Regexp.quote k }.join "|"
  PATTERN = /\A\s*(#{quoted})?\s*(#{Gem::Version::VERSION_PATTERN})\s*\z/

  ##
  # Factory method to create a Gem::Requirement object.  Input may be
  # a Version, a String, or nil.  Intended to simplify client code.
  #
  # If the input is "weird", the default version requirement is
  # returned.

  def self.create input
    case input
    when Gem::Requirement then
      input
    when Gem::Version, Array then
      new input
    else
      if input.respond_to? :to_str then
        new [input.to_str]
      else
        default
      end
    end
  end

  ##
  # A default "version requirement" can surely _only_ be '>= 0'.
  #--
  # This comment once said:
  #
  # "A default "version requirement" can surely _only_ be '> 0'."

  def self.default
    new '>= 0'
  end

  ##
  # Parse +obj+, returning an <tt>[op, version]</tt> pair. +obj+ can
  # be a String or a Gem::Version.
  #
  # If +obj+ is a String, it can be either a full requirement
  # specification, like <tt>">= 1.2"</tt>, or a simple version number,
  # like <tt>"1.2"</tt>.
  #
  #     parse("> 1.0")                 # => [">", "1.0"]
  #     parse("1.0")                   # => ["=", "1.0"]
  #     parse(Gem::Version.new("1.0")) # => ["=,  "1.0"]

  def self.parse obj
    return ["=", obj] if Gem::Version === obj

    unless PATTERN =~ obj.to_s
      raise ArgumentError, "Illformed requirement [#{obj.inspect}]"
    end

    [$1 || "=", Gem::Version.new($2)]
  end

  ##
  # An array of requirement pairs. The first element of the pair is
  # the op, and the second is the Gem::Version.

  attr_reader :requirements #:nodoc:

  ##
  # Constructs a requirement from +requirements+. Requirements can be
  # Strings, Gem::Versions, or Arrays of those. +nil+ and duplicate
  # requirements are ignored. An empty set of +requirements+ is the
  # same as <tt>">= 0"</tt>.

  def initialize *requirements
    requirements = requirements.flatten
    requirements.compact!
    requirements.uniq!

    requirements << ">= 0" if requirements.empty?
    @none = (requirements == ">= 0")
    @requirements = requirements.map! { |r| self.class.parse r }
  end

  def none?
    @none ||= (to_s == ">= 0")
  end

  def as_list # :nodoc:
    requirements.map { |op, version| "#{op} #{version}" }.sort
  end

  def hash # :nodoc:
    requirements.hash
  end

  def marshal_dump # :nodoc:
    fix_syck_default_key_in_requirements

    [@requirements]
  end

  def marshal_load array # :nodoc:
    @requirements = array[0]

    fix_syck_default_key_in_requirements
  end

  def yaml_initialize(tag, vals) # :nodoc:
    vals.each do |ivar, val|
      instance_variable_set "@#{ivar}", val
    end

    fix_syck_default_key_in_requirements
  end

  def init_with coder # :nodoc:
    yaml_initialize coder.tag, coder.map
  end

  def prerelease?
    requirements.any? { |r| r.last.prerelease? }
  end

  def pretty_print q # :nodoc:
    q.group 1, 'Gem::Requirement.new(', ')' do
      q.pp as_list
    end
  end

  ##
  # True if +version+ satisfies this Requirement.

  def satisfied_by? version
    # #28965: syck has a bug with unquoted '=' YAML.loading as YAML::DefaultKey
    requirements.all? { |op, rv| (OPS[op] || OPS["="]).call version, rv }
  end

  alias :=== :satisfied_by?
  alias :=~ :satisfied_by?

  ##
  # True if the requirement will not always match the latest version.

  def specific?
    return true if @requirements.length > 1 # GIGO, > 1, > 2 is silly

    not %w[> >=].include? @requirements.first.first # grab the operator
  end

  def to_s # :nodoc:
    as_list.join ", "
  end

  def <=> other # :nodoc:
    to_s <=> other.to_s
  end

  private

  def fix_syck_default_key_in_requirements
    Gem.load_yaml

    # Fixup the Syck DefaultKey bug
    @requirements.each do |r|
      if r[0].kind_of? Gem::SyckDefaultKey
        r[0] = "="
      end
    end
  end
end

# :stopdoc:
# Gem::Version::Requirement is used in a lot of old YAML specs. It's aliased
# here for backwards compatibility. I'd like to remove this, maybe in RubyGems
# 2.0.

::Gem::Version::Requirement = ::Gem::Requirement
# :startdoc:


##
# The Version class processes string versions into comparable
# values. A version string should normally be a series of numbers
# separated by periods. Each part (digits separated by periods) is
# considered its own number, and these are used for sorting. So for
# instance, 3.10 sorts higher than 3.2 because ten is greater than
# two.
#
# If any part contains letters (currently only a-z are supported) then
# that version is considered prerelease. Versions with a prerelease
# part in the Nth part sort less than versions with N-1
# parts. Prerelease parts are sorted alphabetically using the normal
# Ruby string sorting rules. If a prerelease part contains both
# letters and numbers, it will be broken into multiple parts to
# provide expected sort behavior (1.0.a10 becomes 1.0.a.10, and is
# greater than 1.0.a9).
#
# Prereleases sort between real releases (newest to oldest):
#
# 1. 1.0
# 2. 1.0.b1
# 3. 1.0.a.2
# 4. 0.9
#
# == How Software Changes
#
# Users expect to be able to specify a version constraint that gives them
# some reasonable expectation that new versions of a library will work with
# their software if the version constraint is true, and not work with their
# software if the version constraint is false.  In other words, the perfect
# system will accept all compatible versions of the library and reject all
# incompatible versions.
#
# Libraries change in 3 ways (well, more than 3, but stay focused here!).
#
# 1. The change may be an implementation detail only and have no effect on
#    the client software.
# 2. The change may add new features, but do so in a way that client software
#    written to an earlier version is still compatible.
# 3. The change may change the public interface of the library in such a way
#    that old software is no longer compatible.
#
# Some examples are appropriate at this point.  Suppose I have a Stack class
# that supports a <tt>push</tt> and a <tt>pop</tt> method.
#
# === Examples of Category 1 changes:
#
# * Switch from an array based implementation to a linked-list based
#   implementation.
# * Provide an automatic (and transparent) backing store for large stacks.
#
# === Examples of Category 2 changes might be:
#
# * Add a <tt>depth</tt> method to return the current depth of the stack.
# * Add a <tt>top</tt> method that returns the current top of stack (without
#   changing the stack).
# * Change <tt>push</tt> so that it returns the item pushed (previously it
#   had no usable return value).
#
# === Examples of Category 3 changes might be:
#
# * Changes <tt>pop</tt> so that it no longer returns a value (you must use
#   <tt>top</tt> to get the top of the stack).
# * Rename the methods to <tt>push_item</tt> and <tt>pop_item</tt>.
#
# == RubyGems Rational Versioning
#
# * Versions shall be represented by three non-negative integers, separated
#   by periods (e.g. 3.1.4).  The first integers is the "major" version
#   number, the second integer is the "minor" version number, and the third
#   integer is the "build" number.
#
# * A category 1 change (implementation detail) will increment the build
#   number.
#
# * A category 2 change (backwards compatible) will increment the minor
#   version number and reset the build number.
#
# * A category 3 change (incompatible) will increment the major build number
#   and reset the minor and build numbers.
#
# * Any "public" release of a gem should have a different version.  Normally
#   that means incrementing the build number.  This means a developer can
#   generate builds all day long for himself, but as soon as he/she makes a
#   public release, the version must be updated.
#
# === Examples
#
# Let's work through a project lifecycle using our Stack example from above.
#
# Version 0.0.1:: The initial Stack class is release.
# Version 0.0.2:: Switched to a linked=list implementation because it is
#                 cooler.
# Version 0.1.0:: Added a <tt>depth</tt> method.
# Version 1.0.0:: Added <tt>top</tt> and made <tt>pop</tt> return nil
#                 (<tt>pop</tt> used to return the  old top item).
# Version 1.1.0:: <tt>push</tt> now returns the value pushed (it used it
#                 return nil).
# Version 1.1.1:: Fixed a bug in the linked list implementation.
# Version 1.1.2:: Fixed a bug introduced in the last fix.
#
# Client A needs a stack with basic push/pop capability.  He writes to the
# original interface (no <tt>top</tt>), so his version constraint looks
# like:
#
#   gem 'stack', '~> 0.0'
#
# Essentially, any version is OK with Client A.  An incompatible change to
# the library will cause him grief, but he is willing to take the chance (we
# call Client A optimistic).
#
# Client B is just like Client A except for two things: (1) He uses the
# <tt>depth</tt> method and (2) he is worried about future
# incompatibilities, so he writes his version constraint like this:
#
#   gem 'stack', '~> 0.1'
#
# The <tt>depth</tt> method was introduced in version 0.1.0, so that version
# or anything later is fine, as long as the version stays below version 1.0
# where incompatibilities are introduced.  We call Client B pessimistic
# because he is worried about incompatible future changes (it is OK to be
# pessimistic!).
#
# == Preventing Version Catastrophe:
#
# From: http://blog.zenspider.com/2008/10/rubygems-howto-preventing-cata.html
#
# Let's say you're depending on the fnord gem version 2.y.z. If you
# specify your dependency as ">= 2.0.0" then, you're good, right? What
# happens if fnord 3.0 comes out and it isn't backwards compatible
# with 2.y.z? Your stuff will break as a result of using ">=". The
# better route is to specify your dependency with a "spermy" version
# specifier. They're a tad confusing, so here is how the dependency
# specifiers work:
#
#   Specification From  ... To (exclusive)
#   ">= 3.0"      3.0   ... &infin;
#   "~> 3.0"      3.0   ... 4.0
#   "~> 3.0.0"    3.0.0 ... 3.1
#   "~> 3.5"      3.5   ... 4.0
#   "~> 3.5.0"    3.5.0 ... 3.6

class Gem::Version
  autoload :Requirement, 'rubygems/requirement'

  include Comparable

  VERSION_PATTERN = '[0-9]+(\.[0-9a-zA-Z]+)*' # :nodoc:
  ANCHORED_VERSION_PATTERN = /\A\s*(#{VERSION_PATTERN})*\s*\z/ # :nodoc:

  ##
  # A string representation of this Version.

  attr_reader :version
  alias to_s version

  ##
  # True if the +version+ string matches RubyGems' requirements.

  def self.correct? version
    version.to_s =~ ANCHORED_VERSION_PATTERN
  end

  ##
  # Factory method to create a Version object. Input may be a Version
  # or a String. Intended to simplify client code.
  #
  #   ver1 = Version.create('1.3.17')   # -> (Version object)
  #   ver2 = Version.create(ver1)       # -> (ver1)
  #   ver3 = Version.create(nil)        # -> nil

  def self.create input
    if input.respond_to? :version then
      input
    elsif input.nil? then
      nil
    else
      new input
    end
  end

  ##
  # Constructs a Version from the +version+ string.  A version string is a
  # series of digits or ASCII letters separated by dots.

  def initialize version
    raise ArgumentError, "Malformed version number string #{version}" unless
      self.class.correct?(version)

    @version = version.to_s
    @version.strip!
  end

  ##
  # Return a new version object where the next to the last revision
  # number is one greater (e.g., 5.3.1 => 5.4).
  #
  # Pre-release (alpha) parts, e.g, 5.3.1.b.2 => 5.4, are ignored.

  def bump
    segments = self.segments.dup
    segments.pop while segments.any? { |s| String === s }
    segments.pop if segments.size > 1

    segments[-1] = segments[-1].succ
    self.class.new segments.join(".")
  end

  ##
  # A Version is only eql? to another version if it's specified to the
  # same precision. Version "1.0" is not the same as version "1".

  def eql? other
    self.class === other and @version == other.version
  end

  def hash # :nodoc:
    @hash ||= segments.hash
  end

  def init_with coder # :nodoc:
    yaml_initialize coder.tag, coder.map
  end

  def inspect # :nodoc:
    "#<#{self.class} #{version.inspect}>"
  end

  ##
  # Dump only the raw version string, not the complete object. It's a
  # string for backwards (RubyGems 1.3.5 and earlier) compatibility.

  def marshal_dump
    [version]
  end

  ##
  # Load custom marshal format. It's a string for backwards (RubyGems
  # 1.3.5 and earlier) compatibility.

  def marshal_load array
    initialize array[0]
  end

  def yaml_initialize(tag, map)
    @version = map['version']
    @segments = nil
    @hash = nil
  end

  ##
  # A version is considered a prerelease if it contains a letter.

  def prerelease?
    @prerelease ||= @version =~ /[a-zA-Z]/
  end

  def pretty_print q # :nodoc:
    q.text "Gem::Version.new(#{version.inspect})"
  end

  ##
  # The release for this version (e.g. 1.2.0.a -> 1.2.0).
  # Non-prerelease versions return themselves.

  def release
    return self unless prerelease?

    segments = self.segments.dup
    segments.pop while segments.any? { |s| String === s }
    self.class.new segments.join('.')
  end

  def segments # :nodoc:

    # segments is lazy so it can pick up version values that come from
    # old marshaled versions, which don't go through marshal_load.

    @segments ||= @version.scan(/[0-9]+|[a-z]+/i).map do |s|
      /^\d+$/ =~ s ? s.to_i : s
    end
  end

  ##
  # A recommended version for use with a ~> Requirement.

  def spermy_recommendation
    segments = self.segments.dup

    segments.pop    while segments.any? { |s| String === s }
    segments.pop    while segments.size > 2
    segments.push 0 while segments.size < 2

    "~> #{segments.join(".")}"
  end

  ##
  # Compares this version with +other+ returning -1, 0, or 1 if the
  # other version is larger, the same, or smaller than this
  # one. Attempts to compare to something that's not a
  # <tt>Gem::Version</tt> return +nil+.

  def <=> other
    return unless Gem::Version === other
    return 0 if @version == other.version

    lhsegments = segments
    rhsegments = other.segments

    lhsize = lhsegments.size
    rhsize = rhsegments.size
    limit  = (lhsize > rhsize ? lhsize : rhsize) - 1

    i = 0

    while i <= limit
      lhs, rhs = lhsegments[i] || 0, rhsegments[i] || 0
      i += 1

      next      if lhs == rhs
      return -1 if String  === lhs && Numeric === rhs
      return  1 if Numeric === lhs && String  === rhs

      return lhs <=> rhs
    end

    return 0
  end
end

def require(file)
  # no-op
end
