include $(TOPDIR)/rules.mk

PKG_NAME:=routebot
PKG_VERSION:=0.2.1
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

# sources live two levels up in the repo (CURDIR resolves the feed symlink)
ROUTEBOT_SRC:=$(CURDIR)/../..

define Package/routebot
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=fwmark and CIDR-list policy routing daemon
  DEPENDS:=+libubox +libubus +libuci +libmnl
endef

define Package/routebot/description
  Routes traffic by fwmark or destination CIDR lists through groups of
  interfaces, bundled as resilient ECMP nexthop groups with per-member ICMP
  health checks. Members drop out when down or unhealthy; a group with no
  usable member is blackholed instead of leaking out another uplink.
endef

define Package/routebot/conffiles
/etc/config/routebot
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(ROUTEBOT_SRC)/CMakeLists.txt $(ROUTEBOT_SRC)/LICENSE $(ROUTEBOT_SRC)/src $(PKG_BUILD_DIR)/
endef

define Package/routebot/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/routebot $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/routebot.init $(1)/etc/init.d/routebot
	$(INSTALL_CONF) ./files/routebot.config $(1)/etc/config/routebot
endef

$(eval $(call BuildPackage,routebot))
