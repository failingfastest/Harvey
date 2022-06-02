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

import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.plugin.*;

public class StartOffset {
	public long gdbStart;
	public long ghidraStart;

	public static StartOffset single;

	public static StartOffset get() {
		if (single == null) {
			single = new StartOffset();
		}

		return single;
	}

	public StartOffset() {
		gdbStart = -1;
		ghidraStart = -1;
	}

	public long calculate(HarveyPlugin plugin, String symbol) {
		if (ghidraStart == -1) {
			Program p = plugin.getProgram();
			SymbolTable st = p.getSymbolTable();
			SymbolIterator si = st.getAllSymbols(true);

			Symbol s = si.next();
			while (s != null) {
				if (s.getName().equals(symbol)) {
					break;
				}
				s = si.next();
			}
			ghidraStart = s.getAddress().getUnsignedOffset();
		}
		
		if (gdbStart == -1 || ghidraStart == -1) {
			return -1;
		}

		return ghidraStart - gdbStart;
	}

	public long getOffset() {
		if (gdbStart == -1 || ghidraStart == -1) {
			return -1;
		}

		return ghidraStart - gdbStart;
	}
}
