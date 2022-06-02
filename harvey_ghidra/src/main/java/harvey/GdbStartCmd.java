// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
package harvey;

import harvey.HarveyPlugin;
import harvey.HarveyCmd;
import harvey.StartOffset;

import java.util.function.Function;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class GdbStartCmd extends GdbSymbolCmd {
	public GdbStartCmd() {
		defaults.put("symbol", "_start");
	}

	static public GdbStartCmd create() {
		return new GdbStartCmd();
	}

	public String getCmdName() {
		return "gdbStart";
	}

	String applyImpl(HarveyPlugin plugin, Map<String, String> args) {
		JSONObject cmd = plugin.getSocket().getCmdJsonObj(this);
		cmd.put("cmd", "gdbSymbol");

		JSONObject jargs = (JSONObject)cmd.get("args");
		for (Map.Entry<String,String> entry : args.entrySet()) {
			jargs.put(entry.getKey(), entry.getValue());
		}

		sendCmd(plugin, cmd);

		return "Sending gdbStart command";
	}

	public String handleResult(HarveyPlugin plugin, JSONObject j) {
		plugin.log(j.toJSONString());
		for (Map.Entry<String, String> entry : inArgs.entrySet()) {
			plugin.log(entry.getKey() + ":" + entry.getValue());
		}
		JSONObject r = (JSONObject)j.get("return");
		if (r != null && (boolean)j.get("success") == true) {
			long address = (Long)r.get("output");
			plugin.log("Address: " + Long.toString(address));
			StartOffset.get().gdbStart = address;
			String symbol = inArgs.get("symbol");
			long offset = StartOffset.get().calculate(plugin, symbol);
			plugin.log("Offset: " + Long.toString(offset));
		}

		return "could not find return";
	}
}
