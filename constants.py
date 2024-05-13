"""
Other constants

From https://github.com/ajchellew/zwiftplay/blob/main/zaplibrary/src/main/java/com/che/zap/device/common/ZapConstants.kt
"""

ZWIFT_MANUFACTURER_ID = 2378 # Zwift, Inc

# Zwift Play = RC1
RC1_LEFT_SIDE = bytes([3])
RC1_RIGHT_SIDE = bytes([2])

# Zwift Click = BC1
BC1 = bytes([9])

RIDE_ON = bytes([82, 105, 100, 101, 79, 110])

# these don't actually seem to matter, its just the header has to be 7 bytes RIDEON + 2
REQUEST_START = bytes([1, 2]) # //bytesOf(1, 2)
RESPONSE_START = bytes([1, 3]) # // from device

# Message types received from device
CONTROLLER_NOTIFICATION_MESSAGE_TYPE = bytes([7])
EMPTY_MESSAGE_TYPE = bytes([21])
BATTERY_LEVEL_TYPE = bytes([25])

# not figured out the protobuf type this really is, the content is just two varints.
CLICK_NOTIFICATION_MESSAGE_TYPE = bytes([55])

types = {
    int.to_bytes(7): "CONTROLLER_NOTIFICATION_MESSAGE_TYPE", 
    int.to_bytes(21): "EMPTY_MESSAGE_TYPE", 
    int.to_bytes(25): "BATTERY_LEVEL_TYPE", 
    int.to_bytes(55): "CLICK_NOTIFICATION_MESSAGE_TYPE"
}

# encryption details
KEY_LENGTH = 32
HKDF_LENGTH = 36
MAC_LENGTH = 4
COUNTER_LENGTH = 4
