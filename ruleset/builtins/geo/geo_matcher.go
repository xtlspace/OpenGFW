package geo

import (
	"net"
	"strings"
	"sync"
)

type GeoMatcher struct {
	geoLoader       GeoLoader
	geoSiteMatcher  map[string]hostMatcher
	siteMatcherLock sync.RWMutex
	geoIpMatcher    map[string]hostMatcher
	ipMatcherLock   sync.RWMutex
}

func NewGeoMatcher(geoSiteFilename, geoIpFilename string) *GeoMatcher {
	return &GeoMatcher{
		geoLoader:      NewDefaultGeoLoader(geoSiteFilename, geoIpFilename),
		geoSiteMatcher: make(map[string]hostMatcher),
		geoIpMatcher:   make(map[string]hostMatcher),
	}
}

func (g *GeoMatcher) MatchGeoIp(ip, condition string) bool {
	g.ipMatcherLock.RLock()
	matcher, ok := g.geoIpMatcher[condition]
	g.ipMatcherLock.RUnlock()
	if !ok {
		// Slow path: build the matcher once. Loading the database can be
		// slow, so it is done under the write lock with a double check.
		g.ipMatcherLock.Lock()
		matcher, ok = g.geoIpMatcher[condition]
		if !ok {
			condition = strings.ToLower(condition)
			country := condition
			if len(country) == 0 {
				g.ipMatcherLock.Unlock()
				return false
			}
			gMap, err := g.geoLoader.LoadGeoIP()
			if err != nil {
				g.ipMatcherLock.Unlock()
				return false
			}
			list, ok := gMap[country]
			if !ok || list == nil {
				g.ipMatcherLock.Unlock()
				return false
			}
			matcher, err = newGeoIPMatcher(list)
			if err != nil {
				g.ipMatcherLock.Unlock()
				return false
			}
			g.geoIpMatcher[condition] = matcher
		}
		g.ipMatcherLock.Unlock()
	}
	parseIp := net.ParseIP(ip)
	if parseIp == nil {
		return false
	}
	ipv4 := parseIp.To4()
	if ipv4 != nil {
		return matcher.Match(HostInfo{IPv4: ipv4})
	}
	ipv6 := parseIp.To16()
	if ipv6 != nil {
		return matcher.Match(HostInfo{IPv6: ipv6})
	}
	return false
}

func (g *GeoMatcher) MatchGeoSite(site, condition string) bool {
	g.siteMatcherLock.RLock()
	matcher, ok := g.geoSiteMatcher[condition]
	g.siteMatcherLock.RUnlock()
	if !ok {
		// Slow path: build the matcher once.
		g.siteMatcherLock.Lock()
		matcher, ok = g.geoSiteMatcher[condition]
		if !ok {
			condition = strings.ToLower(condition)
			name, attrs := parseGeoSiteName(condition)
			if len(name) == 0 {
				g.siteMatcherLock.Unlock()
				return false
			}
			gMap, err := g.geoLoader.LoadGeoSite()
			if err != nil {
				g.siteMatcherLock.Unlock()
				return false
			}
			list, ok := gMap[name]
			if !ok || list == nil {
				g.siteMatcherLock.Unlock()
				return false
			}
			matcher, err = newGeositeMatcher(list, attrs)
			if err != nil {
				g.siteMatcherLock.Unlock()
				return false
			}
			g.geoSiteMatcher[condition] = matcher
		}
		g.siteMatcherLock.Unlock()
	}
	return matcher.Match(HostInfo{Name: site})
}

func (g *GeoMatcher) LoadGeoSite() error {
	_, err := g.geoLoader.LoadGeoSite()
	return err
}

func (g *GeoMatcher) LoadGeoIP() error {
	_, err := g.geoLoader.LoadGeoIP()
	return err
}

func parseGeoSiteName(s string) (string, []string) {
	parts := strings.Split(s, "@")
	base := strings.TrimSpace(parts[0])
	attrs := parts[1:]
	for i := range attrs {
		attrs[i] = strings.TrimSpace(attrs[i])
	}
	return base, attrs
}
