require "rsmb/smb"

class NegprotRequest

  def command
    SMB_COM_NEGPROT
  end

  def words
    nil
  end

  def bytes
    "\x02NT LM 0.12\0"
  end

end

class NegprotResponse

  attr_reader :dialectIndex, :securityMode, :capabilities

  def initialize(words, bytes)
    @words = words
    @bytes = bytes
    @dialectIndex, @securityMode, @capabilities = words.unpack("vC@19V")
  end

end
