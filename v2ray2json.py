import json
import base64
import argparse
import re
from urllib.parse import urlparse
from urllib.parse import parse_qs
from urllib.parse import unquote

DEFAULT_PORT = 443
DEFAULT_SECURITY = "auto"
DEFAULT_LEVEL = 8
DEFAULT_NETWORK = "tcp"

TLS = "tls"
REALITY = "reality"
HTTP = "http"


class EConfigType:
    class VMESS:
        protocolScheme = "vmess://"
        protocolName = "vmess"

    class CUSTOM:
        protocolScheme = ""
        protocolName = ""

    class SHADOWSOCKS:
        protocolScheme = "ss://"
        protocolName = "ss"

    class SOCKS:
        protocolScheme = "socks://"
        protocolName = "socks"

    class VLESS:
        protocolScheme = "vless://"
        protocolName = "vless"

    class TROJAN:
        protocolScheme = "trojan://"
        protocolName = "trojan"

    class WIREGUARD:
        protocolScheme = "wireguard://"
        protocolName = "wireguard"

    class FREEDOM:
        protocolScheme = "freedom://"
        protocolName = "freedom"

    class BLACKHOLE:
        protocolScheme = "blackhole://"
        protocolName = "blackhole"


class DomainStrategy:
    AsIs = "AsIs"
    UseIp = "UseIp"
    IpIfNonMatch = "IpIfNonMatch"
    IpOnDemand = "IpOnDemand"


class Fingerprint:
    randomized = "randomized"
    randomizedalpn = "randomizedalpn"
    randomizednoalpn = "randomizednoalpn"
    firefox_auto = "firefox_auto"
    chrome_auto = "chrome_auto"
    ios_auto = "ios_auto"
    android_11_okhttp = "android_11_okhttp"
    edge_auto = "edge_auto"
    safari_auto = "safari_auto"
    _360_auto = "360_auto"
    qq_auto = "qq_auto"


class LogBean:
    access: str
    error: str
    loglevel: str
    dnsLog: bool

    def __init__(self, access: str, error: str, loglevel: str, dnsLog: bool) -> None:
        self.access = access
        self.error = error
        self.loglevel = loglevel
        self.dnsLog = dnsLog


class InboundBean:
    class SniffingBean:
        enabled: bool
        destOverride: list[str]  # str
        metadataOnly: bool

        def __init__(
            self, enabled: bool, destOverride: list[str], metadataOnly: bool
        ) -> None:
            self.enabled = enabled
            self.destOverride = destOverride
            self.metadataOnly = metadataOnly

    class InSettingsBean:
        auth: str = None
        udp: bool = None
        userLevel: int = None
        address: str = None
        port: int = None
        network: str = None

        def __init__(
            self,
            auth: str = None,
            udp: bool = None,
            userLevel: int = None,
            address: str = None,
            port: int = None,
            network: str = None,
        ) -> None:
            self.auth = auth
            self.udp = udp
            self.userLevel = userLevel
            self.address = address
            self.port = port
            self.network = network

    tag: str
    port: int
    protocol: str
    listen: str
    settings: any
    sniffing: SniffingBean
    streamSettings: any
    allocate: any

    def __init__(
        self,
        tag: str,
        port: int,
        protocol: str,
        listen: str,
        settings: any,
        sniffing: SniffingBean,
        streamSettings: any,
        allocate: any,
    ) -> None:
        self.tag = tag
        self.port = port
        self.protocol = protocol
        self.listen = listen
        self.settings = settings
        self.sniffing = sniffing
        self.streamSettings = streamSettings
        self.allocate = allocate


class OutboundBean:
    class OutSettingsBean:
        class VnextBean:
            class UsersBean:
                id: str = ""
                alterId: int = None
                security: str = DEFAULT_SECURITY
                level: int = DEFAULT_LEVEL
                encryption: str = ""
                flow: str = ""

                def __init__(
                    self,
                    id: str = "",
                    alterId: int = None,
                    security: str = DEFAULT_SECURITY,
                    level: int = DEFAULT_LEVEL,
                    encryption: str = "",
                    flow: str = "",
                ) -> None:
                    self.id = id
                    self.alterId = alterId
                    self.security = security
                    self.level = level
                    self.encryption = encryption
                    self.flow = flow

            address: str = ""
            port: int = DEFAULT_PORT
            users: list[UsersBean]  # UsersBean

            def __init__(
                self,
                address: str = "",
                port: int = DEFAULT_PORT,
                users: list[UsersBean] = [],
            ) -> None:
                self.address = address
                self.port = port
                self.users = users

        class ServersBean:
            class SocksUsersBean:
                user: str = ""
                # @SerializedName("pass")
                _pass: str = ""
                level: int = DEFAULT_LEVEL

                def __init__(
                    self, user: str = "", _pass: str = "", level: int = DEFAULT_LEVEL
                ) -> None:
                    self.user = user
                    self._pass = _pass
                    self.level = level

            address: str = ""
            method: str = "chacha20-poly1305"
            ota: bool = False
            password: str = ""
            port: int = DEFAULT_PORT
            level: int = DEFAULT_LEVEL
            email: str = None
            flow: str = None
            ivCheck: bool = None
            users: list[SocksUsersBean] = None  # SocksUsersBean

            def __init__(
                self,
                address: str = "",
                method: str = "chacha20-poly1305",
                ota: bool = False,
                password: str = "",
                port: int = DEFAULT_PORT,
                level: int = DEFAULT_LEVEL,
                email: str = None,
                flow: str = None,
                ivCheck: bool = None,
                users: list[SocksUsersBean] = None,
            ) -> None:
                self.address = address
                self.method = method
                self.ota = ota
                self.password = password
                self.port = port
                self.level = level
                self.email = email
                self.flow = flow
                self.ivCheck = ivCheck
                self.users = users

        class Response:
            type: str

            def __init__(self, type: str) -> None:
                self.type = type

        class WireGuardBean:
            publicKey: str = ""
            endpoint: str = ""

            def __init__(self, publicKey: str = "", endpoint: str = "") -> None:
                self.publicKey = publicKey
                self.endpoint = endpoint

        vnext: list[VnextBean] = None  # VnextBean
        servers: list[ServersBean] = None  # ServersBean
        response: Response = None
        network: str = None
        address: str = None
        port: int = None
        domainStrategy: str = None
        redirect: str = None
        userLevel: int = None
        inboundTag: str = None
        secretKey: str = None
        peers: list[WireGuardBean] = None  # WireGuardBean

        def __init__(
            self,
            vnext: list[VnextBean] = None,
            servers: list[ServersBean] = None,
            response: Response = None,
            network: str = None,
            address: str = None,
            port: int = None,
            domainStrategy: str = None,
            redirect: str = None,
            userLevel: int = None,
            inboundTag: str = None,
            secretKey: str = None,
            peers: list[WireGuardBean] = None,
        ) -> None:
            self.vnext = vnext
            self.servers = servers
            self.response = response
            self.network = network
            self.address = address
            self.port = port
            self.domainStrategy = domainStrategy
            self.redirect = redirect
            self.userLevel = userLevel
            self.inboundTag = inboundTag
            self.secretKey = secretKey
            self.peers = peers

    class StreamSettingsBean:
        class TcpSettingsBean:
            class HeaderBean:
                class RequestBean:
                    class HeadersBean:
                        Host: list[str] = []  # str
                        # @SerializedName("User-Agent")
                        userAgent: list[str] = None  # str
                        # @SerializedName("Accept-Encoding")
                        acceptEncoding: list[str] = None  # str
                        Connection: list[str] = None  # str
                        Pragma: str = None

                        def __init__(
                            self,
                            Host: list[str] = [],
                            userAgent: list[str] = None,
                            acceptEncoding: list[str] = None,
                            Connection: list[str] = None,
                            Pragma: str = None,
                        ) -> None:
                            self.Host = Host
                            self.userAgent = userAgent
                            self.acceptEncoding = acceptEncoding
                            self.Connection = Connection
                            self.Pragma = Pragma

                    path: list[str] = []  # str
                    headers: HeadersBean = HeadersBean()
                    version: str = None
                    method: str = None

                    def __init__(
                        self,
                        path: list[str] = [],
                        headers: HeadersBean = HeadersBean(),
                        version: str = None,
                        method: str = None,
                    ) -> None:
                        self.path = path
                        self.headers = headers
                        self.version = version
                        self.method = method

                type: str = "none"
                request: RequestBean = None

                def __init__(
                    self, type: str = "none", request: RequestBean = None
                ) -> None:
                    self.type = type
                    self.request = request

            header: HeaderBean = HeaderBean()
            acceptProxyProtocol: bool = None

            def __init__(
                self,
                header: HeaderBean = HeaderBean(),
                acceptProxyProtocol: bool = None,
            ) -> None:
                self.header = header
                self.acceptProxyProtocol = acceptProxyProtocol

        class KcpSettingsBean:
            class HeaderBean:
                type: str = "none"

                def __init__(self, type: str = "none") -> None:
                    self.type = type

            mtu: int = 1350
            tti: int = 50
            uplinkCapacity: int = 12
            downlinkCapacity: int = 100
            congestion: bool = False
            readBufferSize: int = 1
            writeBufferSize: int = 1
            header: HeaderBean = HeaderBean()
            seed: str = None

            def __init__(
                self,
                mtu: int = 1350,
                tti: int = 50,
                uplinkCapacity: int = 12,
                downlinkCapacity: int = 100,
                congestion: bool = False,
                readBufferSize: int = 1,
                writeBufferSize: int = 1,
                header: HeaderBean = HeaderBean(),
                seed: str = None,
            ) -> None:
                self.mtu = mtu
                self.tti = tti
                self.uplinkCapacity = uplinkCapacity
                self.downlinkCapacity = downlinkCapacity
                self.congestion = congestion
                self.readBufferSize = readBufferSize
                self.writeBufferSize = writeBufferSize
                self.header = header
                self.seed = seed

        class WsSettingsBean:
            class HeadersBean:
                Host: str = ""

                def __init__(self, Host: str = "") -> None:
                    self.Host = Host

            path: str = ""
            headers: HeadersBean = HeadersBean()
            maxEarlyData: int = None
            useBrowserForwarding: bool = None
            acceptProxyProtocol: bool = None

            def __init__(
                self,
                path: str = "",
                headers: HeadersBean = HeadersBean(),
                maxEarlyData: int = None,
                useBrowserForwarding: bool = None,
                acceptProxyProtocol: bool = None,
            ) -> None:
                self.path = path
                self.headers = headers
                self.maxEarlyData = maxEarlyData
                self.useBrowserForwarding = useBrowserForwarding
                self.acceptProxyProtocol = acceptProxyProtocol

        class HttpSettingsBean:
            host: list[str] = []  # str
            path: str = ""

            def __init__(self, host: list[str] = [], path: str = "") -> None:
                self.host = host
                self.path = path

        class TlsSettingsBean:
            allowInsecure: bool = False
            serverName: str = ""
            alpn: list[str] = None  # str
            minVersion: str = None
            maxVersion: str = None
            preferServerCipherSuites: bool = None
            cipherSuites: str = None
            fingerprint: str = None
            certificates: list[any] = None  # any
            disableSystemRoot: bool = None
            enableSessionResumption: bool = None
            show: bool = False
            publicKey: str = None
            shortId: str = None
            spiderX: str = None

            def __init__(
                self,
                allowInsecure: bool = False,
                serverName: str = "",
                alpn: list[str] = None,
                minVersion: str = None,
                maxVersion: str = None,
                preferServerCipherSuites: bool = None,
                cipherSuites: str = None,
                fingerprint: str = None,
                certificates: list[any] = None,
                disableSystemRoot: bool = None,
                enableSessionResumption: bool = None,
                show: bool = False,
                publicKey: str = None,
                shortId: str = None,
                spiderX: str = None,
            ) -> None:
                self.allowInsecure = allowInsecure
                self.serverName = serverName
                self.alpn = alpn
                self.minVersion = minVersion
                self.maxVersion = maxVersion
                self.preferServerCipherSuites = preferServerCipherSuites
                self.cipherSuites = cipherSuites
                self.fingerprint = fingerprint
                self.certificates = certificates
                self.disableSystemRoot = disableSystemRoot
                self.enableSessionResumption = enableSessionResumption
                self.show = show
                self.publicKey = publicKey
                self.shortId = shortId
                self.spiderX = spiderX

        class QuicSettingBean:
            class HeaderBean:
                type: str = "none"

                def __init__(self, type: str = "none") -> None:
                    self.type = type

            security: str = "none"
            key: str = ""
            header: HeaderBean = HeaderBean()

            def __init__(
                self,
                security: str = "none",
                key: str = "",
                header: HeaderBean = HeaderBean(),
            ) -> None:
                self.security = security
                self.key = key
                self.header = header

        class GrpcSettingsBean:
            serviceName: str = ""
            multiMode: bool = None

            def __init__(self, serviceName: str = "", multiMode: bool = None) -> None:
                self.serviceName = serviceName
                self.multiMode = multiMode

        network: str = DEFAULT_NETWORK
        security: str = ""
        tcpSettings: TcpSettingsBean = None
        kcpSettings: KcpSettingsBean = None
        wsSettings: WsSettingsBean = None
        httpSettings: HttpSettingsBean = None
        tlsSettings: TlsSettingsBean = None
        quicSettings: QuicSettingBean = None
        realitySettings: TlsSettingsBean = None
        grpcSettings: GrpcSettingsBean = None
        dsSettings: any = None
        sockopt: any = None

        def __init__(
            self,
            network: str = DEFAULT_NETWORK,
            security: str = "",
            tcpSettings: TcpSettingsBean = None,
            kcpSettings: KcpSettingsBean = None,
            wsSettings: WsSettingsBean = None,
            httpSettings: HttpSettingsBean = None,
            tlsSettings: TlsSettingsBean = None,
            quicSettings: QuicSettingBean = None,
            realitySettings: TlsSettingsBean = None,
            grpcSettings: GrpcSettingsBean = None,
            dsSettings: any = None,
            sockopt: any = None,
        ) -> None:
            self.network = network
            self.security = security
            self.tcpSettings = tcpSettings
            self.kcpSettings = kcpSettings
            self.wsSettings = wsSettings
            self.httpSettings = httpSettings
            self.tlsSettings = tlsSettings
            self.quicSettings = quicSettings
            self.realitySettings = realitySettings
            self.grpcSettings = grpcSettings
            self.dsSettings = dsSettings
            self.sockopt = sockopt

        def populateTransportSettings(
            self,
            transport: str,
            headerType: str,
            host: str,
            path: str,
            seed: str,
            quicSecurity: str,
            key: str,
            mode: str,
            serviceName: str,
        ) -> str:
            sni = ""
            self.network = transport
            if self.network == "tcp":
                tcpSetting = self.TcpSettingsBean()
                if headerType == HTTP:
                    tcpSetting.header.type = HTTP
                    if host != "" or path != "":
                        requestObj = self.TcpSettingsBean.HeaderBean.RequestBean()
                        requestObj.headers.Host = (
                            "" if host == None else host.split(",")
                        )
                        requestObj.path = "" if path == None else path.split(",")
                        tcpSetting.header.request = requestObj
                        sni = (
                            requestObj.headers.Host[0]
                            if len(requestObj.headers.Host) > 0
                            else sni
                        )
                else:
                    tcpSetting.header.type = "none"
                    sni = host if host != "" else ""
                self.tcpSetting = tcpSetting

            elif self.network == "kcp":
                kcpsetting = self.KcpSettingsBean()
                kcpsetting.header.type = headerType if headerType != None else "none"
                if seed == None or seed == "":
                    kcpsetting.seed = None
                else:
                    kcpsetting.seed = seed
                self.kcpSettings = kcpsetting

            elif self.network == "ws":
                wssetting = self.WsSettingsBean()
                wssetting.headers.Host = host if host != None else ""
                sni = wssetting.headers.Host
                wssetting.path = path if path != None else "/"
                self.wsSettings = wssetting

            elif self.network == "h2" or self.network == "http":
                network = "h2"
                h2Setting = self.HttpSettingsBean()
                h2Setting.host = "" if host == None else host.split(",")
                sni = h2Setting.host[0] if len(h2Setting.host) > 0 else sni
                h2Setting.path = path if path != None else "/"
                self.httpSettings = h2Setting

            elif self.network == "quic":
                quicsetting = self.QuicSettingBean()
                quicsetting.security = quicSecurity if quicSecurity != None else "none"
                quicsetting.key = key if key != None else ""
                quicsetting.header.type = headerType if headerType != None else "none"
                self.quicSettings = quicsetting

            elif self.network == "grpc":
                grpcSetting = self.GrpcSettingsBean()
                grpcSetting.multiMode = mode == "multi"
                grpcSetting.serviceName = serviceName if serviceName != None else ""
                sni = host if host != None else ""
                self.grpcSettings = grpcSetting

            return sni

        def populateTlsSettings(
            self,
            streamSecurity: str,
            allowInsecure: bool,
            sni: str,
            fingerprint: str,
            alpns: str,
            publicKey: str,
            shortId: str,
            spiderX: str,
        ):
            self.security = streamSecurity
            tlsSetting = self.TlsSettingsBean(
                allowInsecure=allowInsecure,
                serverName=sni,
                fingerprint=fingerprint,
                alpn=None if alpns == None or alpns == "" else alpns.split(","),
                publicKey=publicKey,
                shortId=shortId,
                spiderX=spiderX,
            )

            if self.security == TLS:
                self.tlsSettings = tlsSetting
                self.realitySettings = None
            elif self.security == REALITY:
                self.tlsSettings = None
                self.realitySettings = tlsSetting

    class MuxBean:
        enabled: bool
        concurrency: int

        def __init__(self, enabled: bool, concurrency: int = 8):
            self.enabled = enabled
            self.concurrency = concurrency

    tag: str = "proxy"
    protocol: str
    settings: OutSettingsBean = None
    streamSettings: StreamSettingsBean = None
    proxySettings: any = None
    sendThrough: str = None
    mux: MuxBean = MuxBean(False)

    def __init__(
        self,
        tag: str = "proxy",
        protocol: str = None,
        settings: OutSettingsBean = None,
        streamSettings: StreamSettingsBean = None,
        proxySettings: any = None,
        sendThrough: str = None,
        mux: MuxBean = MuxBean(enabled=False),
    ):
        self.tag = tag
        self.protocol = protocol
        self.settings = settings
        self.streamSettings = streamSettings
        self.proxySettings = proxySettings
        self.sendThrough = sendThrough
        self.mux = mux


class DnsBean:
    class ServersBean:
        address: str = ""
        port: int = None
        domains: list[str] = None  # str
        expectIPs: list[str] = None  # str
        clientIp: str = None

        def __init__(
            self,
            address: str = "",
            port: int = None,
            domains: list[str] = None,
            expectIPs: list[str] = None,
            clientIp: str = None,
        ) -> None:
            self.address = address
            self.port = port
            self.domains = domains
            self.expectIPs = expectIPs
            self.clientIp = clientIp

    servers: list[any] = None  # any
    hosts: list = None  # map(str, any)
    clientIp: str = None
    disableCache: bool = None
    queryStrategy: str = None
    tag: str = None

    def __init__(
        self,
        servers: list[any] = None,
        hosts: list = None,
        clientIp: str = None,
        disableCache: bool = None,
        queryStrategy: str = None,
        tag: str = None,
    ) -> None:
        self.servers = servers
        self.hosts = hosts
        self.clientIp = clientIp
        self.disableCache = disableCache
        self.queryStrategy = queryStrategy
        self.tag = tag


class RoutingBean:
    class RulesBean:
        type: str = ""
        ip: list[str] = None  # str
        domain: list[str] = None  # str
        outboundTag: str = ""
        balancerTag: str = None
        port: str = None
        sourcePort: str = None
        network: str = None
        source: list[str] = None  # str
        user: list[str] = None  # str
        inboundTag: list[str] = None  # str
        protocol: list[str] = None  # str
        attrs: str = None
        domainMatcher: str = None

        def __init__(
            self,
            type: str = "",
            ip: list[str] = None,
            domain: list[str] = None,
            outboundTag: str = "",
            balancerTag: str = None,
            port: str = None,
            sourcePort: str = None,
            network: str = None,
            source: list[str] = None,
            user: list[str] = None,
            inboundTag: list[str] = None,
            protocol: list[str] = None,
            attrs: str = None,
            domainMatcher: str = None,
        ) -> None:
            self.type = type
            self.ip = ip
            self.domain = domain
            self.outboundTag = outboundTag
            self.balancerTag = balancerTag
            self.port = port
            self.sourcePort = sourcePort
            self.network = network
            self.source = source
            self.user = user
            self.inboundTag = inboundTag
            self.protocol = protocol
            self.attrs = attrs
            self.domainMatcher = domainMatcher

    domainStrategy: str
    domainMatcher: str = None
    rules: list[RulesBean]  # RulesBean
    balancers: list[any]  # any

    def __init__(
        self,
        domainStrategy: str,
        domainMatcher: str = None,
        rules: list[RulesBean] = [],
        balancers: list[any] = [],
    ) -> None:
        self.domainStrategy = domainStrategy
        self.domainMatcher = domainMatcher
        self.rules = rules
        self.balancers = balancers


class FakednsBean:
    ipPool: str = "198.18.0.0/15"
    poolSize: int = 10000

    def __init__(self, ipPool: str = "198.18.0.0/15", poolSize: int = 10000) -> None:
        self.ipPool = ipPool
        self.poolSize = poolSize


class PolicyBean:
    class LevelBean:
        handshake: int = None
        connIdle: int = None
        uplinkOnly: int = None
        downlinkOnly: int = None
        statsUserUplink: bool = None
        statsUserDownlink: bool = None
        bufferSize: int = None

        def __init__(
            self,
            handshake: int = None,
            connIdle: int = None,
            uplinkOnly: int = None,
            downlinkOnly: int = None,
            statsUserUplink: bool = None,
            statsUserDownlink: bool = None,
            bufferSize: int = None,
        ) -> None:
            self.handshake = handshake
            self.connIdle = connIdle
            self.uplinkOnly = uplinkOnly
            self.downlinkOnly = downlinkOnly
            self.statsUserUplink = statsUserUplink
            self.statsUserDownlink = statsUserDownlink
            self.bufferSize = bufferSize

    levels: list  # map(str, LevelBean)
    system: any = None

    def __init__(self, levels: list, system: any = None) -> None:
        self.levels = levels
        self.system = system


class Comment:
    remark: str = None

    def __init__(self, remark: str = None) -> None:
        self.remark = remark


class V2rayConfig:
    _comment: Comment = None
    stats: any = None
    log: LogBean
    policy: PolicyBean
    inbounds: list[InboundBean]  # InboundBean
    outbounds: list[OutboundBean]  # OutboundBean
    dns: DnsBean
    routing: RoutingBean
    api: any = None
    transport: any = None
    reverse: any = None
    fakedns: any = None
    browserForwarder: any = None

    def __init__(
        self,
        _comment: Comment = None,
        stats: any = None,
        log: LogBean = None,
        policy: PolicyBean = None,
        inbounds: list = None,
        outbounds: list = None,
        dns: DnsBean = None,
        routing: RoutingBean = None,
        api: any = None,
        transport: any = None,
        reverse: any = None,
        fakedns: any = None,
        browserForwarder: any = None,
    ) -> None:
        self.stats = stats
        self._comment = _comment
        self.log = log
        self.policy = policy
        self.inbounds = inbounds
        self.outbounds = outbounds
        self.dns = dns
        self.routing = routing
        self.api = api
        self.transport = transport
        self.reverse = reverse
        self.fakedns = fakedns
        self.browserForwarder = browserForwarder


class VmessQRCode:
    v: str = ""
    ps: str = ""
    add: str = ""
    port: str = ""
    id: str = ""
    aid: str = "0"
    scy: str = ""
    net: str = ""
    type: str = ""
    host: str = ""
    path: str = ""
    tls: str = ""
    sni: str = ""
    alpn: str = ""
    allowInsecure: str = ""

    def __init__(
        self,
        v: str = "",
        ps: str = "",
        add: str = "",
        port: str = "",
        id: str = "",
        aid: str = "0",
        scy: str = "",
        net: str = "",
        type: str = "",
        host: str = "",
        path: str = "",
        tls: str = "",
        sni: str = "",
        alpn: str = "",
        allowInsecure: str = "",
        fp: str = "",
    ):
        self.v = v
        self.ps = ps
        self.add = add
        self.port = port
        self.id = id
        self.aid = aid
        self.scy = scy
        self.net = net
        self.type = type
        self.host = host
        self.path = path
        self.tls = tls
        self.sni = sni
        self.alpn = alpn
        self.allowInsecure = allowInsecure
        self.fp = fp


def remove_nulls(d):
    if isinstance(d, dict):
        for k, v in list(d.items()):
            if v is None:
                del d[k]
            else:
                remove_nulls(v)
    if isinstance(d, list):
        for v in d:
            remove_nulls(v)
    return d


def get_log():
    log = LogBean(access="", error="", loglevel="error", dnsLog=False)
    return log


def get_inbound():
    inbound = InboundBean(
        tag="in_proxy",
        port=1080,
        protocol=EConfigType.SOCKS.protocolName,
        listen="127.0.0.1",
        settings=InboundBean.InSettingsBean(
            auth="noauth",
            udp=True,
            userLevel=8,
        ),
        sniffing=InboundBean.SniffingBean(
            enabled=False,
            destOverride=None,
            metadataOnly=None,
        ),
        streamSettings=None,
        allocate=None,
    )
    return inbound


def get_outbound_vmess():
    outbound = OutboundBean(
        protocol=EConfigType.VMESS.protocolName,
        settings=OutboundBean.OutSettingsBean(
            vnext=[
                OutboundBean.OutSettingsBean.VnextBean(
                    users=[OutboundBean.OutSettingsBean.VnextBean.UsersBean()],
                ),
            ]
        ),
        streamSettings=OutboundBean.StreamSettingsBean(),
    )
    return outbound


def get_outbound_vless():
    outbound = OutboundBean(
        protocol=EConfigType.VLESS.protocolName,
        settings=OutboundBean.OutSettingsBean(
            vnext=[
                OutboundBean.OutSettingsBean.VnextBean(
                    users=[OutboundBean.OutSettingsBean.VnextBean.UsersBean()],
                ),
            ]
        ),
        streamSettings=OutboundBean.StreamSettingsBean(),
    )
    return outbound


def get_outbound_trojan():
    outbound = OutboundBean(
        protocol=EConfigType.TROJAN.protocolName,
        settings=OutboundBean.OutSettingsBean(
            servers=[OutboundBean.OutSettingsBean.ServersBean()]
        ),
        streamSettings=OutboundBean.StreamSettingsBean(),
    )
    return outbound


def get_outbound_ss():
    outbound = OutboundBean(
        protocol="shadowsocks",
        settings=OutboundBean.OutSettingsBean(
            servers=[OutboundBean.OutSettingsBean.ServersBean()]
        ),
        streamSettings=OutboundBean.StreamSettingsBean(),
    )
    return outbound


def try_resolve_resolve_sip002(str: str, config: OutboundBean):
    try:
        uri = urlparse(str)
        config.remarks = unquote(uri.fragment or "")

        if ":" in uri.username:
            arr_user_info = list(map(str.strip, uri.username.split(":")))
            if len(arr_user_info) != 2:
                return False
            method = arr_user_info[0]
            password = unquote(arr_user_info[1])
        else:
            base64_decode = base64.b64decode(uri.username).decode(
                encoding="utf-8", errors="ignore"
            )
            arr_user_info = list(map(str.strip, base64_decode.split(":")))
            if len(arr_user_info) < 2:
                return False
            method = arr_user_info[0]
            password = base64_decode.split(":", 1)[1]

        server = config.outbound_bean.settings.servers[0]
        server.address = uri.hostname
        server.port = uri.port
        server.password = password
        server.method = method

        return True
    except Exception as e:
        return False


def get_outbound1():
    outbound1 = OutboundBean(
        tag="direct",
        protocol=EConfigType.FREEDOM.protocolName,
        settings=OutboundBean.OutSettingsBean(
            domainStrategy=DomainStrategy.UseIp,
        ),
        mux=None,
    )
    return outbound1


def get_outbound2():
    outbound2 = OutboundBean(
        tag="blackhole",
        protocol=EConfigType.BLACKHOLE.protocolName,
        settings=OutboundBean.OutSettingsBean(),
        mux=None,
    )
    return outbound2


def get_dns(dns_list=["8.8.8.8"]):
    if isinstance(dns_list, str):
        if "," in dns_list:
            dns_list = dns_list.split(",")

    dns = DnsBean(servers=dns_list)
    return dns


def get_routing():
    routing = RoutingBean(domainStrategy=DomainStrategy.UseIp)
    return routing


def generateConfig(config: str, dns_list=["8.8.8.8"]):
    allowInsecure = True

    temp = config.split("://")
    protocol = temp[0]
    raw_config = temp[1]

    if protocol == EConfigType.VMESS.protocolName:
        _len = len(raw_config)
        if _len % 4 > 0:
            raw_config += "=" * (4 - _len % 4)

        b64decode = base64.b64decode(raw_config).decode(
            encoding="utf-8", errors="ignore"
        )
        _json = json.loads(b64decode, strict=False)

        vmessQRCode_attributes = list(VmessQRCode.__dict__["__annotations__"].keys())
        for key in list(_json.keys()):
            if key not in vmessQRCode_attributes:
                del _json[key]

        vmessQRCode = VmessQRCode(**_json)

        outbound = get_outbound_vmess()

        vnext = outbound.settings.vnext[0]
        vnext.address = vmessQRCode.add
        vnext.port = (
            int(vmessQRCode.port) if vmessQRCode.port.isdigit() else DEFAULT_PORT
        )

        user = vnext.users[0]
        user.id = vmessQRCode.id
        user.security = vmessQRCode.scy if vmessQRCode.scy != "" else DEFAULT_SECURITY
        user.alterId = int(vmessQRCode.aid) if vmessQRCode.aid.isdigit() else None

        streamSetting = outbound.streamSettings

        sni = streamSetting.populateTransportSettings(
            transport=vmessQRCode.net,
            headerType=vmessQRCode.type,
            host=vmessQRCode.host,
            path=vmessQRCode.path,
            seed=vmessQRCode.path,
            quicSecurity=vmessQRCode.host,
            key=vmessQRCode.path,
            mode=vmessQRCode.type,
            serviceName=vmessQRCode.path,
        )

        fingerprint = (
            vmessQRCode.fp
            if vmessQRCode.fp
            else streamSetting.tlsSettings.fingerprint
            if streamSetting.tlsSettings
            else None
        )

        streamSetting.populateTlsSettings(
            streamSecurity=vmessQRCode.tls,
            allowInsecure=allowInsecure,
            sni=sni if vmessQRCode.sni == "" else vmessQRCode.sni,
            fingerprint=fingerprint,
            alpns=vmessQRCode.alpn,
            publicKey=None,
            shortId=None,
            spiderX=None,
        )

        v2rayConfig = V2rayConfig(
            _comment=Comment(remark=vmessQRCode.ps),
            log=get_log(),
            inbounds=[get_inbound()],
            outbounds=[outbound, get_outbound1(), get_outbound2()],
            dns=get_dns(dns_list=dns_list),
            routing=get_routing(),
        )

        v2rayConfig_str_json = json.dumps(v2rayConfig, default=vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)

    elif protocol == EConfigType.VLESS.protocolName:
        parsed_url = urlparse(config)
        _netloc = parsed_url.netloc.split("@")

        name = parsed_url.fragment
        uid = _netloc[0]
        hostname = _netloc[1].rsplit(":", 1)[0]
        port = int(_netloc[1].rsplit(":", 1)[1])

        netquery = dict(
            (k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(parsed_url.query).items()
        )

        outbound = get_outbound_vless()

        streamSetting = outbound.streamSettings
        fingerprint = (
            netquery.get("fp")
            if "fp" in netquery
            else streamSetting.tlsSettings.fingerprint
            if streamSetting.tlsSettings
            else None
        )

        vnext = outbound.settings.vnext[0]
        vnext.address = hostname
        vnext.port = port

        user = vnext.users[0]
        user.id = uid
        user.encryption = netquery.get("encryption", "none")
        user.flow = netquery.get("flow", "")

        sni = streamSetting.populateTransportSettings(
            transport=netquery.get("type", "tcp"),
            headerType=netquery.get("headerType", None),
            host=netquery.get("host", None),
            path=netquery.get("path", None),
            seed=netquery.get("seed", None),
            quicSecurity=netquery.get("quicSecurity", None),
            key=netquery.get("key", None),
            mode=netquery.get("mode", None),
            serviceName=netquery.get("serviceName", None),
        )
        streamSetting.populateTlsSettings(
            streamSecurity=netquery.get("security", ""),
            allowInsecure=allowInsecure,
            sni=sni if netquery.get("sni", None) == None else netquery.get("sni", None),
            fingerprint=fingerprint,
            alpns=netquery.get("alpn", None),
            publicKey=netquery.get("pbk", ""),
            shortId=netquery.get("sid", ""),
            spiderX=netquery.get("spx", ""),
        )

        v2rayConfig = V2rayConfig(
            _comment=Comment(remark=name),
            log=get_log(),
            inbounds=[get_inbound()],
            outbounds=[outbound, get_outbound1(), get_outbound2()],
            dns=get_dns(dns_list=dns_list),
            routing=get_routing(),
        )

        v2rayConfig_str_json = json.dumps(v2rayConfig, default=vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)

    elif protocol == EConfigType.TROJAN.protocolName:
        parsed_url = urlparse(config)
        _netloc = parsed_url.netloc.split("@")

        name = parsed_url.fragment
        uid = _netloc[0]
        hostname = _netloc[1].rsplit(":", 1)[0]
        port = int(_netloc[1].rsplit(":", 1)[1])

        netquery = dict(
            (k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(parsed_url.query).items()
        )

        outbound = get_outbound_trojan()

        streamSetting = outbound.streamSettings

        flow = ""
        fingerprint = (
            streamSetting.tlsSettings.fingerprint
            if streamSetting.tlsSettings != None
            else Fingerprint.randomized
        )

        if len(netquery) > 0:
            sni = streamSetting.populateTransportSettings(
                transport=netquery.get("type", "tcp"),
                headerType=netquery.get("headerType", None),
                host=netquery.get("host", None),
                path=netquery.get("path", None),
                seed=netquery.get("seed", None),
                quicSecurity=netquery.get("quicSecurity", None),
                key=netquery.get("key", None),
                mode=netquery.get("mode", None),
                serviceName=netquery.get("serviceName", None),
            )

            streamSetting.populateTlsSettings(
                streamSecurity=netquery.get("security", TLS),
                allowInsecure=allowInsecure,
                sni=sni
                if netquery.get("sni", None) == None
                else netquery.get("sni", None),
                fingerprint=fingerprint,
                alpns=netquery.get("alpn", None),
                publicKey=None,
                shortId=None,
                spiderX=None,
            )

            flow = netquery.get("flow", "")

        else:
            streamSetting.populateTlsSettings(
                streamSecurity=TLS,
                allowInsecure=allowInsecure,
                sni="",
                fingerprint=fingerprint,
                alpns=None,
                publicKey=None,
                shortId=None,
                spiderX=None,
            )

        server = outbound.settings.servers[0]
        server.address = hostname
        server.port = port
        server.password = uid
        server.flow = flow

        v2rayConfig = V2rayConfig(
            _comment=Comment(remark=name),
            log=get_log(),
            inbounds=[get_inbound()],
            outbounds=[outbound, get_outbound1(), get_outbound2()],
            dns=get_dns(dns_list=dns_list),
            routing=get_routing(),
        )

        v2rayConfig_str_json = json.dumps(v2rayConfig, default=vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)

    elif protocol == EConfigType.SHADOWSOCKS.protocolName:
        outbound = get_outbound_ss()
        if not try_resolve_resolve_sip002(raw_config, outbound):
            result = raw_config.replace(EConfigType.SHADOWSOCKS.protocolScheme, "")
            index_split = result.find("#")
            if index_split > 0:
                try:
                    outbound.remarks = unquote(result[index_split + 1 :])
                except Exception as e:
                    None  # print(e)

                result = result[:index_split]

            # part decode
            index_s = result.find("@")
            result = (
                base64.b64decode(result[:index_s]).decode(
                    encoding="utf-8", errors="ignore"
                )
                + result[index_s:]
                if index_s > 0
                else base64.b64decode(result).decode(encoding="utf-8", errors="ignore")
            )

            legacy_pattern = re.compile(r"^(.+?):(.*)@(.+):(\d+)\/?.*$")
            match = legacy_pattern.match(result)

            if not match:
                raise Exception("Incorrect protocol")

            server = outbound.settings.servers[0]
            server.address = match.group(3).strip("[]")
            server.port = int(match.group(4))
            server.password = match.group(2)
            server.method = match.group(1).lower()

            v2rayConfig = V2rayConfig(
                _comment=Comment(remark=outbound.remarks),
                log=get_log(),
                inbounds=[get_inbound()],
                outbounds=[outbound, get_outbound1(), get_outbound2()],
                dns=get_dns(dns_list=dns_list),
                routing=get_routing(),
            )

            v2rayConfig_str_json = json.dumps(v2rayConfig, default=vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="v2ray2json convert vmess, vless, trojan, ... link to client json config."
    )
    parser.add_argument(
        "config",
        nargs="?",
        help="A vmess://, vless://, trojan://, ... link.",
    )

    option = parser.parse_args()
    config = option.config

    print(generateConfig(config))
