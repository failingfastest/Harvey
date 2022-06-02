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

import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.plugin.*;

public class BreakCmd extends RemoteHarveyCmd {
	public BreakCmd() {
		params.put("label", "string");
	}

	static public BreakCmd create() {
		return new BreakCmd();
	}

	public String getCmdName() {
		return "break";
	}

	String applyImpl(HarveyPlugin plugin, Map<String, String> args) {
		JSONObject cmd = plugin.getSocket().getCmdJsonObj(this);
		long offset = StartOffset.get().getOffset();
		if (offset == -1) {
			return "error: offset not calculated";
		}

		JSONObject jargs = (JSONObject)cmd.get("args");
		String label = args.get("label");
		Program p = plugin.getProgram();

		SymbolTable st = p.getSymbolTable();
		SymbolIterator si = st.getAllSymbols(true);
		Symbol s = si.next();
		long address = -1;
		while (s != null) {
			if (s.getName().equals(label)) {
				address = s.getAddress().getUnsignedOffset();
				address -= offset;
				break;
			}
			s = si.next();
		}

		if (address == -1) {
			return "error: could not resolve symbol: " + label;
		} 

		jargs.put("address", address);
		
		sendCmd(plugin, cmd);

		return "Sending break command";
	}

	public String handleResult(HarveyPlugin plugin, JSONObject j) {
		plugin.log(j.toJSONString());
		
		return "Success";
	}
}
