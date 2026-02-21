# passcheck

CLI password entropy and strength analyzer written in Ruby.

## Features

- Entropy calculation
- Strength scoring (0-100)
- Common pattern detection
- Secure password generation

## Usage

Analyze password:

ruby passcheck.rb -p MyPassword123!

Generate secure password:

ruby passcheck.rb -g 24
