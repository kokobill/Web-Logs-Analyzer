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


        //Helper method to return parsed log file in JSON format
        public JsonResult Parse( string filePath ) {

            //init
            List<LoggedRequest> loggedRequests = new List<LoggedRequest>();
            int allLines = 0;
            int invalidLines = 0;
            int validLines = 0;
            //NCSA common log format regex pattern
            string logEntryPattern = "^([\\d.]+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(.+?)\" (\\d{3}) (\\d+) \"([^\"]+)\" \"([^\"]+)\"";

            //Iterate file
            foreach (string logEntry in System.IO.File.ReadLines(filePath).ToList()) {
                allLines++;
                Match logLineMatch = Regex.Match(logEntry, logEntryPattern);
                if (logLineMatch != null) {
                    try {
                        int tmpFileSize;
                        int fileSize;
                        //Get request from LogLine
                        string lineRequest = logLineMatch.Groups[5].Value;
                        //Get Resource Request
                        string[] requestData = lineRequest.Split(' ');
                        //Get File from Resource
                        string requestFile = requestData[1].Split('/').LastOrDefault().Split('?').FirstOrDefault();
                        //Validate ACTUAL file with extension etc
                        if (!ValidateRequestedFile(requestFile) ) {
                            invalidLines++;
                            continue;
                        }
                        //Get request IP
                        string lineIp = logLineMatch.Groups[1].Value;
                        //Get request Timestamp (UTC)
                        string lineDate = logLineMatch.Groups[4].Value.Split(':').FirstOrDefault() ;
                        //Get request Method
                        string requestMethod = requestData[0];
                        //Get request file extension
                        string requestFileExtension = requestFile.Split('.').LastOrDefault();
                        //Get response code
                        string responseCode = logLineMatch.Groups[6].Value;
                        //Get Requested File Size
                        string fileSizeS = logLineMatch.Groups[7].Value;
                        //Parse filesize 
                        bool result = Int32.TryParse(fileSizeS, out tmpFileSize);
                        if (result) {
                            fileSize = tmpFileSize;
                        }else {
                            fileSize = 0;
                        }
                        //Get Client Info
                        string clientInfo = logLineMatch.Groups[4].Value;
                        validLines++;
                        //Populate loggedRequests list
                        loggedRequests.Add(new LoggedRequest() {
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

            //Get 20 most popular filetypes and AVG filesizes
            var top20CommmonFilesRequests = loggedRequests.GroupBy(a => a.fileExtension).OrderByDescending(top => top.Count()).Take(20)
                                    .Select(a => new RequestedFile() { avgSize = a.Average(b => b.fileSize), extension = a.Key })
                                    .OrderByDescending(a => a.avgSize)
                                    .ToList();

            //Get list of response codes and total filesizes
            var responsesByHttpCode = loggedRequests.GroupBy(a => a.responseCode).OrderByDescending(top => top.Count())
                                    .Select(a => new DataTransferedByResponse() { totalSize = a.Sum(b => b.fileSize/1024), responseCode = a.Key })
                                    .ToList();

            //Get data volumes by date list
            var dataTransferedByDay = loggedRequests.GroupBy(a => a.date)
                                    .Select(a => new DataTransferedByDay() { totalSize = a.Sum(b => b.fileSize / 1024), date = a.Key }).OrderBy(o=>o.date)
                                    .ToList();


            return Json(new { FiletypesGraphData=top20CommmonFilesRequests, ResponsesGraphData=responsesByHttpCode, DailyTransfersGraphData=dataTransferedByDay }, JsonRequestBehavior.AllowGet);
        }




        //Validates if requested file is an actual (and possibly valid file)
        public static bool ValidateRequestedFile(string resource) {
            //TODO Default web media files
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