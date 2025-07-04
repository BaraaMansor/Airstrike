from pydantic import BaseModel, Field

class AttackRequest(BaseModel):
    """Defines the request body for a generic attack requiring a target."""
    target: str = Field()


class DhcpFloodRequest(BaseModel):
    """Defines the request body for the DHCP Flood attack, requiring a network interface."""
    interface: str = Field()
   
 
class deauthRequest(BaseModel):
    mac: str = Field()
    interface: str = Field()
    bssid: str = Field() 