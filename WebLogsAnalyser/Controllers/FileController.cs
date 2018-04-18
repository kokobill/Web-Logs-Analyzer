using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Data;
using System.Text.RegularExpressions;

namespace WebLogsAnalyser.Controllers
{
    public class FileController : Controller
    {
        //GET: @ /File/Index
        public ActionResult Index() {
            //Flag unavailable file
            ViewBag.ReadyToAnalyze = false;
            return View();
        }

        //GET: @ /File/Index
        public FileContentResult DownloadSample() {
            string filename = "apache_logs.txt";
            string filepath = AppDomain.CurrentDomain.BaseDirectory + "/Resources/LogFileSample/" + filename;
            byte[] filedata = System.IO.File.ReadAllBytes(filepath);
            string contentType = MimeMapping.GetMimeMapping(filepath);

            var cd = new System.Net.Mime.ContentDisposition {
                FileName = filename,
                Inline = false,
            };

            Response.AppendHeader("Content-Disposition", cd.ToString());

            return File(filedata, contentType);
        }


        //POST: Handles uploading file action
        [HttpPost]
        public ActionResult Index(HttpPostedFileBase file) {
            //Flag unavailable file
            ViewBag.ReadyToAnalyze = false;
            //Validate Uploaded File
            if (file != null && file.ContentLength > 0) {
                try {
                    //Get filename
                    var fileName = Path.GetFileName(file.FileName);
                    //Store tmpFile for extra checks
                    var tmpPath = Path.Combine(Server.MapPath("~/Resources/tmp"), "tmp"+ fileName + DateTime.Now.ToString("yyyyMMddHHmmssfff"));
                    file.SaveAs(tmpPath);
                    //Detect malicious file
                    if (DetectExecutable(tmpPath)) {
                        ViewBag.Message = "MALICIOUS FILE";
                        System.IO.File.Delete(tmpPath);
                        return View("Index");
                    } else {
                        //Validate file contains logs
                        if (ValidateLog(tmpPath)) {
                            System.IO.File.Delete(tmpPath);
                            //Store File with unique name
                            var path = Path.Combine(Server.MapPath("~/Resources/UploadedLogFiles"), DateTime.Now.ToString("yyyyMMddHHmmssfff") + "_" + fileName);
                            file.SaveAs(path);
                            ViewBag.Message = "File uploaded successfully";
                            ViewBag.UploadedFilePath = path;
                            ViewBag.ReadyToAnalyze = true;
                        }else {
                            ViewBag.Message = "Invalid Log file";
                            System.IO.File.Delete(tmpPath);
                            return View("Index");
                        }
                    }
                }
                catch (Exception ex) {
                    //Return special case exception
                    ViewBag.Message = "ERROR:" + ex.Message.ToString();
                }
            } else {
                ViewBag.Message = "You have not specified a file.";
            }

            //Parse Uploaded file data 
            var ParsedData = new GraphController().Parse(ViewBag.UploadedFilePath);
            ViewBag.FiletypesGraphData = ParsedData.Data.FiletypesGraphData;
            ViewBag.ResponsesGraphData = ParsedData.Data.ResponsesGraphData;
            ViewBag.DailyTransfersGraphData = ParsedData.Data.DailyTransfersGraphData;


            return View("Index");
        }









        //Detects a hidden executable file masked as text file (WINDOWS MZ-exe )
        public static bool DetectExecutable(string filePath) {
            var firstBytes = new byte[2];
            using (var fileStream = System.IO.File.Open(filePath, FileMode.Open)) {
                fileStream.Read(firstBytes, 0, 2);
            }
            return Encoding.UTF8.GetString(firstBytes) == "MZ";
        }

        //Validates that file contains actual Logs
        public static bool ValidateLog(string filePath) {
            string fLine = System.IO.File.ReadLines(filePath).First();
            string logEntryPattern = "^([\\d.]+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(.+?)\" (\\d{3}) (\\d+) \"([^\"]+)\" \"([^\"]+)\"";
            Match regexMatch = Regex.Match(fLine, logEntryPattern);
            return regexMatch.Success;
        }


    }


}