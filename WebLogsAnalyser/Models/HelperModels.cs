using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebLogsAnalyser.Models {
    public class LoggedRequest {
        public string ip { get; set; }
        public string date { get; set; }
        public string request { get; set; }
        public string responseCode { get; set; }
        public string method { get; set; }
        public string file { get; set; }
        public string fileExtension { get; set; }
        public int fileSize { get; set; }
    }

    public class RequestedFile {
        public string extension { get; set; }
        public double avgSize { get; set; }
    }

    public class DataTransferedByResponse {
        public string responseCode { get; set; }
        public long totalSize { get; set; }
    }

    public class DataTransferedByDay {
        public string date { get; set; }
        public long totalSize { get; set; }
    }
}