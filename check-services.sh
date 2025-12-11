#!/bin/bash
# FastReactCMS Service Health Check
# Run on production server to diagnose service issues

echo "🔍 FastReactCMS Service Health Check"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root (for systemctl)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠️  Not running as root. Some checks may require sudo.${NC}"
    SUDO="sudo"
else
    SUDO=""
fi

# Function to check service status
check_service() {
    local service=$1
    local name=$2

    if $SUDO systemctl is-active --quiet $service; then
        echo -e "${GREEN}✅ $name is running${NC}"
        return 0
    else
        echo -e "${RED}❌ $name is NOT running${NC}"
        echo -e "   💡 Fix: ${YELLOW}sudo systemctl start $service${NC}"
        return 1
    fi
}

# Check Backend API
echo "📡 Backend API Service"
check_service "fastreactcms-backend" "Backend API"
if [ $? -eq 0 ]; then
    # Test API endpoint
    if curl -s http://localhost:8100/health > /dev/null 2>&1; then
        echo -e "   ${GREEN}└─ Health endpoint responding${NC}"
    else
        echo -e "   ${RED}└─ Health endpoint not responding${NC}"
    fi
fi
echo ""

# Check SSR Server
echo "🎨 SSR Server Service"
check_service "fastreactcms-ssr" "SSR Server"
if [ $? -eq 0 ]; then
    # Test SSR health endpoint
    if curl -s http://localhost:3001/health > /dev/null 2>&1; then
        echo -e "   ${GREEN}└─ Health endpoint responding${NC}"
        # Get cache stats
        cache_info=$(curl -s http://localhost:3001/health)
        cache_size=$(echo $cache_info | grep -o '"cache_size":[0-9]*' | grep -o '[0-9]*')
        cache_max=$(echo $cache_info | grep -o '"cache_max":[0-9]*' | grep -o '[0-9]*')
        if [ ! -z "$cache_size" ]; then
            echo -e "   └─ Cache: $cache_size/$cache_max pages"
        fi
    else
        echo -e "   ${RED}└─ Health endpoint not responding${NC}"
    fi
fi
echo ""

# Check NGINX
echo "🌐 NGINX Web Server"
if $SUDO systemctl is-active --quiet nginx; then
    echo -e "${GREEN}✅ NGINX is running${NC}"
    # Test config
    if $SUDO nginx -t > /dev/null 2>&1; then
        echo -e "   ${GREEN}└─ Configuration is valid${NC}"
    else
        echo -e "   ${RED}└─ Configuration has errors${NC}"
        echo -e "   💡 Run: ${YELLOW}sudo nginx -t${NC}"
    fi
else
    echo -e "${RED}❌ NGINX is NOT running${NC}"
    echo -e "   💡 Fix: ${YELLOW}sudo systemctl start nginx${NC}"
fi
echo ""

# Check PostgreSQL
echo "🗄️  PostgreSQL Database"
if $SUDO systemctl is-active --quiet postgresql; then
    echo -e "${GREEN}✅ PostgreSQL is running${NC}"
    # Check if database exists
    if $SUDO -u postgres psql -lqt | cut -d \| -f 1 | grep -qw fastreactcms; then
        echo -e "   ${GREEN}└─ Database 'fastreactcms' exists${NC}"
    else
        echo -e "   ${RED}└─ Database 'fastreactcms' not found${NC}"
    fi
else
    echo -e "${RED}❌ PostgreSQL is NOT running${NC}"
    echo -e "   💡 Fix: ${YELLOW}sudo systemctl start postgresql${NC}"
fi
echo ""

# Recent logs
echo "📋 Recent Service Logs (Last 5 lines)"
echo "--------------------------------------"
echo ""
echo -e "${YELLOW}Backend API:${NC}"
$SUDO journalctl -u fastreactcms-backend -n 5 --no-pager 2>/dev/null || echo "  No logs available"
echo ""
echo -e "${YELLOW}SSR Server:${NC}"
$SUDO journalctl -u fastreactcms-ssr -n 5 --no-pager 2>/dev/null || echo "  No logs available"
echo ""

# Summary
echo "======================================"
echo "📊 Summary"
echo "======================================"
echo ""
echo "To view detailed logs:"
echo -e "  Backend:    ${YELLOW}sudo journalctl -u fastreactcms-backend -f${NC}"
echo -e "  SSR:        ${YELLOW}sudo journalctl -u fastreactcms-ssr -f${NC}"
echo -e "  NGINX:      ${YELLOW}sudo tail -f /var/log/nginx/theitapprentice.error.log${NC}"
echo ""
echo "To restart services:"
echo -e "  Backend:    ${YELLOW}sudo systemctl restart fastreactcms-backend${NC}"
echo -e "  SSR:        ${YELLOW}sudo systemctl restart fastreactcms-ssr${NC}"
echo -e "  NGINX:      ${YELLOW}sudo systemctl restart nginx${NC}"
echo ""
echo "To check service status:"
echo -e "  ${YELLOW}sudo systemctl status fastreactcms-backend${NC}"
echo -e "  ${YELLOW}sudo systemctl status fastreactcms-ssr${NC}"
echo ""
