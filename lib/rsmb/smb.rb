module SMB

  # Constants for flags

  module Flags

    SUPPORT_LOCKREAD     = 0x01
    CLIENT_BUF_AVAIL     = 0x02
    RESERVED             = 0x04
    CASELESS_PATHNAMES   = 0x08
    CANONICAL_PATHNAMES  = 0x10
    REQUEST_OPLOCK       = 0x20
    REQUEST_BATCH_OPLOCK = 0x40
    REPLY                = 0x80

  end

  # Constants for flags2

  module Flags2

    LONG_PATH_COMPONENTS    = 0x0001
    EXTENDED_ATTRIBUTES     = 0x0002
    SMB_SECURITY_SIGNATURES = 0x0004
    IS_LONG_NAME            = 0x0040
    EXTENDED_SECURITY       = 0x0800 
    DFS_PATHNAMES           = 0x1000
    READ_PERMIT_EXECUTE     = 0x2000
    U32_BIT_ERROR_CODES     = 0x4000 
    UNICODE_STRINGS         = 0x8000

  end

  # Commands

  module Commands

    NEGPROT    = 0x72
    SESSSETUPX = 0x73

  end

end
