#!/usr/bin/env ruby

require 'optparse'
require 'securerandom'

options = {}

OptionParser.new do |opts|
  opts.banner = "Usage: passcheck.rb [options]"

  opts.on("-pPASSWORD", "--password=PASSWORD", "Password to analyze") do |p|
    options[:password] = p
  end

  opts.on("-gLENGTH", "--generate=LENGTH", Integer, "Generate strong password (default 20)") do |l|
    options[:generate] = l || 20
  end
end.parse!

# Charset completo sicuro
LOWER   = ('a'..'z').to_a
UPPER   = ('A'..'Z').to_a
DIGITS  = ('0'..'9').to_a
SYMBOLS = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
           '-', '_', '=', '+', '[', ']', '{', '}', ';', ':',
           ',', '.', '<', '>', '?', '/', '~', '`', '|', '\\']

COMMON_PATTERNS = [
  /1234/,
  /password/i,
  /qwerty/i,
  /(.)\1{2,}/
]

def charset_size(password)
  size = 0
  size += 26 if password.match?(/[a-z]/)
  size += 26 if password.match?(/[A-Z]/)
  size += 10 if password.match?(/[0-9]/)
  size += SYMBOLS.length if password.match?(/[[:punct:]]/)
  size
end

def entropy(password)
  return 0 if charset_size(password) == 0
  (password.length * Math.log2(charset_size(password))).round(2)
end

def score_from_entropy(ent)
  case ent
  when 0..40 then 20
  when 41..60 then 50
  when 61..80 then 75
  else 95
  end
end

def strength_label(score)
  case score
  when 0..30 then "Weak"
  when 31..60 then "Moderate"
  when 61..85 then "Strong"
  else "Very Strong"
  end
end

def analyze(password)
  ent = entropy(password)
  score = score_from_entropy(ent)

  feedback = []

  feedback << "Increase length to at least 16 characters" if password.length < 16
  feedback << "Add uppercase letters" unless password.match?(/[A-Z]/)
  feedback << "Add lowercase letters" unless password.match?(/[a-z]/)
  feedback << "Add numbers" unless password.match?(/[0-9]/)
  feedback << "Add special characters" unless password.match?(/[[:punct:]]/)

  COMMON_PATTERNS.each do |pattern|
    feedback << "Avoid common pattern: #{pattern.source}" if password.match?(pattern)
  end

  {
    length: password.length,
    entropy: ent,
    score: score,
    strength: strength_label(score),
    feedback: feedback
  }
end

def generate_password(length = 20)
  all_chars = LOWER + UPPER + DIGITS + SYMBOLS

  # Garantisce almeno una categoria
  password = []
  password << LOWER.sample
  password << UPPER.sample
  password << DIGITS.sample
  password << SYMBOLS.sample

  (length - 4).times { password << all_chars.sample }

  password.shuffle.join
end

# ===== MAIN =====

if options[:generate]
  puts generate_password(options[:generate])
  exit
end

if options[:password]
  result = analyze(options[:password])

  puts "\n=== Password Analysis ==="
  puts "Length: #{result[:length]}"
  puts "Entropy: #{result[:entropy]} bits"
  puts "Score: #{result[:score]}/100"
  puts "Strength: #{result[:strength]}"

  unless result[:feedback].empty?
    puts "\nSuggestions:"
    result[:feedback].each { |f| puts "- #{f}" }
  else
    puts "\nNo major weaknesses detected."
  end
else
  puts "Use -p to analyze or -g LENGTH to generate."
end