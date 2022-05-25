// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
package harvey;

import harvey.HarveyPlugin;

import java.util.function.Function;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;

public class HarveyCmd {
	public HarveyCmd() {
		params = new HashMap<String, String>();
		hexChars = new HashMap<Character, Integer>();
		hexChars.put('0', 0);
		hexChars.put('1', 1);
		hexChars.put('2', 2);
		hexChars.put('3', 3);
		hexChars.put('4', 4);
		hexChars.put('5', 5);
		hexChars.put('6', 6);
		hexChars.put('7', 7);
		hexChars.put('8', 8);
		hexChars.put('9', 9);
		hexChars.put('a', 0xa);
		hexChars.put('b', 0xb);
		hexChars.put('c', 0xc);
		hexChars.put('d', 0xd);
		hexChars.put('e', 0xe);
		hexChars.put('f', 0xf);
	}

	public Map<String, String> params;
	public Map<Character, Integer> hexChars;
	public String id;

	public void setId(String id_) {
		id = id_;
	}

	public String getName() {
		return null;
	}

	public boolean checkTypes(Map<String, String> args) {
		for (Map.Entry<String, String> v : args.entrySet()) {
			String param = v.getKey();
			String type = params.get(param);
			if (type == null) {
				return false;
			}
			if (type.equals("int")) {
				return checkInt(v.getValue());
			} else if (type.equals("string")) {
				return checkString(v.getValue());
			} else if (type.equals("hexBytes")) {
				return checkHexBytes(v.getValue());
			} else if (type.equals("bool")) {
				return checkBool(v.getValue());
			}

		}

		return false;
	}

	boolean checkInt(String value) {
		try {
			Integer.decode(value);
		} catch (NumberFormatException nfe) {
		}
		return true;
	}

	boolean checkBool(String value) {
		String canon = value.toLowerCase();
		if (canon.equals("true") || canon.equals("false")) {
			return true;
		}
		return false;
	}

	boolean checkString(String value) {
		return true;
	}

	boolean checkHexBytes(String value) {
		String canon = value.toLowerCase();

		if (canon.length() % 2 == 1) {
			return false;
		}

		for (var c : canon.toCharArray()) {
			if (!hexChars.containsKey(c)) {
				return false;
			}
		}
		return true;
	}

	String apply(HarveyPlugin plugin, Map<String, String> args) {
		if (!checkTypes(args)) {
			return "error: bad arguments";
		}
		return applyImpl(plugin, args);
	}

	String applyImpl(HarveyPlugin plugin, Map<String, String> args) {
		return "error: not implemented";
	}
}
