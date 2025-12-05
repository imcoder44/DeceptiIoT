from aiohttp import web
import logging
from core.logger import log_event
from core.detector import analyze_event

routes = web.RouteTableDef()

@routes.get('/')
async def index(request):
    ip = request.remote
    await analyze_event(log_event(ip, 8080, "HTTP", "GET /"))
    # Return a fake router login page
    html_content = """
    <html><head><title>Router Login</title></head>
    <body style='background-color:#f0f0f0; font-family:sans-serif; text-align:center; padding-top:50px;'>
    <h2>Broadband Router Gateway</h2>
    <form action='/login' method='POST'>
    <input type='text' name='user' placeholder='Username'><br><br>
    <input type='password' name='pass' placeholder='Password'><br><br>
    <input type='submit' value='Login'>
    </form>
    </body></html>
    """
    return web.Response(text=html_content, content_type='text/html')

@routes.post('/login')
async def login(request):
    ip = request.remote
    data = await request.post()
    user = data.get('user', '')
    password = data.get('pass', '')
    
    evt = log_event(ip, 8080, "HTTP", "POST /login", user, password)
    await analyze_event(evt)
    
    return web.Response(text="<html><body><h1>Error 500: Internal Server Error</h1></body></html>", status=500)

@routes.get('/setup.xml')
async def upnp_xml(request):
    ip = request.remote
    await analyze_event(log_event(ip, 8080, "HTTP", "GET /setup.xml"))
    xml = """<root xmlns="urn:schemas-upnp-org:device-1-0">
        <specVersion><major>1</major><minor>0</minor></specVersion>
        <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
        <friendlyName>Wireless Router</friendlyName>
        <manufacturer>Generic IoT</manufacturer>
        </device></root>"""
    return web.Response(text=xml, content_type='text/xml')

async def start_http_honeypot():
    app = web.Application()
    app.add_routes(routes)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8080)
    logging.info("HTTP Honeypot active on port 8080")
    await site.start()