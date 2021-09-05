require 'openssl'

class Array
  def ^(other)
    zip(other).map { |a, b| a ^ b }
  end
end

def print_hex(str)
  str.unpack('C*').each_with_index do |char, index|
    print char.to_s(16).rjust(2, '0') + ' '
    print "\r\n" if (index + 1) % 8 == 0
  end
end

def hmac(digest_name, key, message)
  digest_instance = OpenSSL::Digest.new(digest_name)

  byte_length = digest_instance.block_length
  i_pad = Array.new(byte_length, 0x36)
  o_pad = Array.new(byte_length, 0x5c)

  key_arr = key
  key_arr = key.unpack('C*') if key.instance_of? String
  key_arr = key_arr[0..byte_length] + [0] * (byte_length - key_arr.length)

  appended_i_pad_key = key_arr ^ i_pad
  appended_o_pad_key = key_arr ^ o_pad

  i_pad_key_str = appended_i_pad_key.pack('C*')
  o_pad_key_str = appended_o_pad_key.pack('C*')

  digest = ->(data) { OpenSSL::Digest.digest(digest_name, data) }

  # HMAC式であるH(K XOR opad, H(K XOR ipad, text))
  digest.call(o_pad_key_str + digest.call(i_pad_key_str + message))
end

puts 'my hmac'
print_hex hmac('sha256', 'secretkey0123456', 'hmac test')

puts 'expected'
print_hex OpenSSL::HMAC.digest('sha256', 'secretkey0123456', 'hmac test')
