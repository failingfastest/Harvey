// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
package harvey;

import harvey.HarveyPlugin;
import harvey.HarveyCmd;

import java.util.function.Function;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class GdbRawCmd extends RemoteHarveyCmd {
	public GdbRawCmd() {
		params.put("cmd", "string");
	}

	static public GdbRawCmd create() {
		return new GdbRawCmd();
	}

	public String getCmdName() {
		return "gdbRaw";
	}

	public String handleResult(HarveyPlugin plugin, JSONObject j) {
		plugin.log(j.toJSONString());

		JSONObject result = (JSONObject)j.get("return");
		if (result != null) {
			String output = (String)result.get("output");
			if (output != null) {
				plugin.log("gdb output: " + output);
				return "Success";
			}
		}

		return "could not find return";
	}

	String applyImpl(HarveyPlugin plugin, Map<String, String> args) {
		JSONObject cmd = plugin.getSocket().getCmdJsonObj(this);

		JSONObject jargs = (JSONObject)cmd.get("args");
		for (Map.Entry<String,String> entry : args.entrySet()) {
			jargs.put(entry.getKey(), entry.getValue());
		}

		sendCmd(plugin, cmd);

		return "Sending gdb raw command: " + args.get("cmd");
	}
}
