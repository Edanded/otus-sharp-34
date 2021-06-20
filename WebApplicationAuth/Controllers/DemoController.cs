using Microsoft.AspNetCore.Mvc;

namespace WebApplicationAuth.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    public class DemoController : ControllerBase
    {
        [HttpGet("getNumber/{param}")]
        public string GetMyMethod(int param)
        {
            return $"Your number is {param}";
        }
    }
}