from pydantic import BaseModel
from typing import Optional, List


class DeviceUpdate(BaseModel):
    custom_name: Optional[str] = None
    hostname:    Optional[str] = None


class SettingUpdate(BaseModel):
    value: str


class PluginConfigSave(BaseModel):
    config: dict


class IdentityUpdate(BaseModel):
    vendor_override:      Optional[str] = None
    device_type_override: Optional[str] = None


class MetadataUpdate(BaseModel):
    notes:        Optional[str]  = None
    tags:         Optional[str]  = None
    location:     Optional[str]  = None
    is_important: Optional[bool] = None
    zone:         Optional[str]  = None
    is_ignored:   Optional[bool] = None
    suppress_presence_events: Optional[bool] = None
    person_id:    Optional[str]  = None


class PrimaryIPUpdate(BaseModel):
    ip_address: str


class BlockScheduleCreate(BaseModel):
    mac_address:   Optional[str] = None
    mac_addresses: List[str]     = []
    tags:          str           = ""
    label:         Optional[str] = None
    days_of_week:  str           = "mon,tue,wed,thu,fri,sat,sun"
    start_time:    str
    end_time:      str
    enabled:       bool          = True
    person_id:     Optional[str] = None
    person_ids:    List[str]     = []


class BlockScheduleUpdate(BaseModel):
    label:         Optional[str]       = None
    days_of_week:  Optional[str]       = None
    start_time:    Optional[str]       = None
    end_time:      Optional[str]       = None
    enabled:       Optional[bool]      = None
    mac_addresses: Optional[List[str]] = None
    tags:          Optional[str]       = None
    person_id:     Optional[str]       = None
    person_ids:    Optional[List[str]] = None


class LoginRequest(BaseModel):
    username:    str
    password:    str
    remember_me: bool = False


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str


class SetupUserRequest(BaseModel):
    username: str
    password: str


class SetupNetworkRequest(BaseModel):
    ip_range:   Optional[str] = None
    dns_server: Optional[str] = None
    gateway:    Optional[str] = None


class SetupCompleteRequest(BaseModel):
    vuln_scan_enabled:     bool  = False
    vuln_scan_schedule:    str   = "disabled"
    vuln_scan_on_new:      bool  = False
    notifications_enabled: bool  = True
    ntfy_topic:            str   = ""
    ntfy_url:              str   = "https://ntfy.sh"
    gotify_url:            str   = ""
    gotify_token:          str   = ""
    pushbullet_api_key:    str   = ""
    alert_webhook_url:     str   = ""
    docker_enabled:        bool  = False
    docker_host:           str   = "unix:///var/run/docker.sock"
    fingerbank_api_key:    str   = ""
    timezone:              str   = "UTC"
    auto_update_enabled:   bool  = False
    auto_update_hour:      int   = 3
    auto_update_days:      list  = []


class AutoUpdateRequest(BaseModel):
    enabled: bool
    hour:    int  = 3
    days:    list = []


class ContainerHostCreate(BaseModel):
    name:       str
    type:       str           = "docker_local"
    url:        Optional[str] = None
    auth_user:  Optional[str] = None
    auth_token: Optional[str] = None
    tls_verify: bool          = False
    enabled:    bool          = True
    node:       str           = "pve"
    local_ip:   Optional[str] = None


class ContainerHostUpdate(BaseModel):
    name:       Optional[str]  = None
    type:       Optional[str]  = None
    url:        Optional[str]  = None
    auth_user:  Optional[str]  = None
    auth_token: Optional[str]  = None
    tls_verify: Optional[bool] = None
    enabled:    Optional[bool] = None
    node:       Optional[str]  = None
    local_ip:   Optional[str]  = None


class DockerContainerCreate(BaseModel):
    host_id:       Optional[int] = None
    name:          Optional[str] = None
    image:         Optional[str] = None
    command:       Optional[str | List[str]] = None
    entrypoint:    Optional[str | List[str]] = None
    environment:   Optional[dict | List[str]] = None
    ports:         Optional[dict | List[str]] = None
    volumes:       Optional[dict | List[str]] = None
    networks:      Optional[List[str]] = None
    network:       Optional[str] = None
    restart_policy: str = "no"
    privileged:    bool = False
    working_dir:   Optional[str] = None
    hostname:      Optional[str] = None
    compose_yaml:  Optional[str] = None
    compose_service: Optional[str] = None
    proxmox_node: Optional[str] = None
    vmid:          Optional[int] = None
    ostemplate:    Optional[str] = None
    storage:       Optional[str] = None
    disk_gb:       int = 8
    cores:         int = 1
    memory_mb:     int = 512
    swap_mb:       int = 512
    ip_address:    Optional[str] = None
    gateway:       Optional[str] = None


class GroupAddRequest(BaseModel):
    primary_mac: str


class ZoneAssign(BaseModel):
    mac_addresses: List[str]
    zone:          Optional[str] = None


class ZoneRename(BaseModel):
    old_name: str
    new_name: str


class SavedViewCreate(BaseModel):
    name:    str
    filters: dict = {}
    columns: list = []


class SuppressionCreate(BaseModel):
    mac_address: Optional[str] = None
    event_type:  str
    until:       Optional[str] = None
    reason:      Optional[str] = None


class ChannelCreate(BaseModel):
    name:    str
    service: str
    config:  dict = {}
    enabled: bool = True


class ProfileCreate(BaseModel):
    name:       str
    enabled:    bool      = True
    events:     dict      = {}
    channel_ids: List[int] = []


class WolPayload(BaseModel):
    mac: str
    ip:  Optional[str] = None


class PersonCreate(BaseModel):
    name:         str
    primary_mac:  Optional[str]  = None
    photo:       Optional[str]  = None
    notes:        Optional[str]  = None
    mac_addresses: List[str]     = []


class PersonUpdate(BaseModel):
    name:        Optional[str] = None
    primary_mac: Optional[str] = None
    photo:       Optional[str]  = None
    notes:       Optional[str]  = None


class PersonDeviceAdd(BaseModel):
    mac_address: str
    set_primary: bool = False


class PersonBlockRequest(BaseModel):
    duration_minutes: Optional[int] = None
