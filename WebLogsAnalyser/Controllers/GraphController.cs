using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Mvc;
using WebLogsAnalyser.Models;

namespace WebLogsAnalyser.Controllers
{
    public class GraphController : Controller
    {
        // GET: Graph
        public ActionResult Index()
        {
            return View();
        }



        public JsonResult Parse( string filePath ) {

            List<LoggedRequest> filesRequests = new List<LoggedRequest>();
            int allLines = 0;
            int invalidLines = 0;
            int validLines = 0;
       
            string logEntryPattern = "^([\\d.]+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(.+?)\" (\\d{3}) (\\d+) \"([^\"]+)\" \"([^\"]+)\"";

            foreach (string logEntry in System.IO.File.ReadLines(filePath).ToList()) {
                allLines++;
                Match lineRegex = Regex.Match(logEntry, logEntryPattern);
                if (lineRegex != null) {
                    try {
                        int tmpFileSize;
                        int fileSize;
                        //Get request from LogLine
                        string lineRequest = lineRegex.Groups[5].Value;
                        //Get Resource Request
                        string[] requestData = lineRequest.Split(' ');
                        //Get File from Resource
                        string requestFile = requestData[1].Split('/').LastOrDefault().Split('?').FirstOrDefault();
                        //Validate ACTUAL file with extension etc
                        if (!ValidateResourceFile(requestFile) ) {
                            invalidLines++;
                            continue;
                        }
                        //Get request IP
                        string lineIp = lineRegex.Groups[1].Value;
                        //Get request Timestamp (UTC)
                        string lineDate = lineRegex.Groups[4].Value.Split(':').FirstOrDefault() ;
                        //Get request Method
                        string requestMethod = requestData[0];
                        //Get request file extension
                        string requestFileExtension = requestFile.Split('.').LastOrDefault();
                        //Get response code
                        string responseCode = lineRegex.Groups[6].Value;
                        //Get Requested File Size
                        string fileSizeS = lineRegex.Groups[7].Value;
                        bool result = Int32.TryParse(fileSizeS, out tmpFileSize);
                        if (result) {
                            fileSize = tmpFileSize;
                        }else {
                            fileSize = 0;
                        }
                        //Get Client Info
                        string clientInfo = lineRegex.Groups[4].Value;
                        validLines++;
                        filesRequests.Add(new LoggedRequest() {
                                ip = lineIp,
                                date = lineDate,
                                request = lineRequest,
                                responseCode = responseCode,
                                method = requestMethod,
                                file = requestFile,
                                fileExtension = requestFileExtension,
                                fileSize = fileSize});
                    }
                    catch (Exception ex) {
                        //Return msg in case of exception
                        invalidLines++;
                        ViewBag.Message = "ERROR:" + ex.Message.ToString();
                    }
                }
            }
            var top20CommmonFilesRequests = filesRequests.GroupBy(a => a.fileExtension).OrderByDescending(top => top.Count()).Take(20)
                                    .Select(a => new RequestedFile() { avgSize = a.Average(b => b.fileSize), extension = a.Key })
                                    .OrderByDescending(a => a.avgSize)
                                    .ToList();

            var responsesByHttpCode = filesRequests.GroupBy(a => a.responseCode).OrderByDescending(top => top.Count())
                                    .Select(a => new DataTransferedByResponse() { totalSize = a.Sum(b => b.fileSize/1024), responseCode = a.Key })
                                    .ToList();

            var dataTransferedByDay = filesRequests.GroupBy(a => a.date)
                                    .Select(a => new DataTransferedByDay() { totalSize = a.Sum(b => b.fileSize / 1024), date = a.Key }).OrderBy(o=>o.date)
                                    .ToList();


            return Json(new { FiletypesGraphData=top20CommmonFilesRequests, ResponsesGraphData=responsesByHttpCode, DailyTransfersGraphData=dataTransferedByDay }, JsonRequestBehavior.AllowGet);
        }


        //Validates if resource is an actual possibly valid file
        public static bool ValidateResourceFile(string resource) {
            //Validate file HAS extension
            if (!resource.Contains('.')) {
                return false;
            }
            //Validate extension 
            string fileExt = resource.Split('.').LastOrDefault();
            string fileExtRegex = @"^[a-zA-Z0-9]+$";
            Match regexMatch = Regex.Match(fileExt, fileExtRegex);
            if (!regexMatch.Success) {
                return false;
            }
            //TODO overkill???
            //Validate filename integrity on OS
            System.IO.FileInfo fi = null;
            try {fi = new System.IO.FileInfo(resource);}
            catch (ArgumentException) { }
            catch (System.IO.PathTooLongException) { }
            catch (NotSupportedException) { }
            return !ReferenceEquals(fi, null);
        }

    }
}