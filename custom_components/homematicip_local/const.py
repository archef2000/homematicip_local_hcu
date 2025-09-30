from homeassistant.const import Platform

DOMAIN = "homematicip_local"

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.EVENT,
    Platform.LIGHT,
    Platform.CLIMATE,
    Platform.SWITCH,
]
