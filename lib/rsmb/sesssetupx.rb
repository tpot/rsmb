require "rsmb/smb"

class SessionSetupAndXRequest

  def initialize
    @ansiPassword = ""
    @unicodePassword = ""
    @accountName = ""
    @primaryDomain = ""
  end

  def command
    SMB::Commands::SESSSETUPX
  end

  def words
    [@ansiPassword, @unicodePassword, 0, @accountName, 0, @primaryDomain, 0, "iOS", 0, "rsmb", 0].pack("a*a*Ca*va*va*va*v")
  end

  def bytes
    [0xff,                    # andXCommand
     0,                       # reserved
     0,                       # andXOffset
     65535,                   # maxBufferSize
     0,                       # maxMpxCount
     0,                       # vcNumber
     0,                       # sessionKey
     @ansiPassword.length,    # caseInsensitivePasswordLength
     @unicodePassword.length, # caseSensitivePasswordLength
     0,                       # reserved
     0                        # capabilities
     ].pack("CCvvvvVvvVV")
  end

end

class SessionSetupAndXResponse

  def initialize(words, bytes)
    @words = words
    @bytes = bytes
  end

end
