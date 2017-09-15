import json
import os
import sys
import pexpect
import subprocess

if len(sys.argv) != 3:
    print("Usage: python " + sys.argv[0] + " <path to sample> <execution time>")
    exit(-1)

dirname, filename = os.path.split(os.path.abspath(__file__))
scriptname = "/root/run-mba.sh"
samplename = sys.argv[1]
exectime = sys.argv[2]
targetpath = "/root/" + samplename.split("/")[-1]

output = {"stat": "",
        "messagetype": "",
        "message": ""
        }

os.chdir("/root/")

try:
    child = pexpect.spawn(scriptname, timeout = 3600)

    index = child.expect(["VNC server running", pexpect.EOF, pexpect.TIMEOUT])

    if index == 0:
        child.sendline("mba_start_dba \"" + samplename + "\" " + exectime + " \"/root/dba_config\"")

        index = child.expect(["Task 0 has finished", "Previous command failed.[^\n\r]*[\n\r]+"])

        if index == 0:
            child.sendline("mba_show_dba_result 0 \"" + targetpath +"\"")

            child.expect("Finished writing results into targeted files")
            child.sendline("q")
            child.expect(pexpect.EOF)

            mba_report = [targetpath+".itrace" , targetpath+".report", targetpath+".strace"]

            output["stat"] = "success"
            output["messagetype"] = "string"
            
            for report in mba_report:
                with open(report) as f:
                    output["message"] += f.read()

            for report in mba_report:
                os.remove(report)

        elif index == 1:
            output["stat"] = "error"
            output["messagetype"] = "string"
            output["message"] = child.after.decode("ascii").strip()
            child.sendline("q")
            child.expect(pexpect.EOF)

    else:
        output["stat"] = "error"
        output["messagetype"] = "string"
        output["message"] = "Failed to execute {}".format(scriptname)

    child.close()

except Exception as e:
    output["stat"] = "error"
    output["messagetype"] = "string"
    output["message"] = str(e)

finally:
    print(json.dumps(output))

    
