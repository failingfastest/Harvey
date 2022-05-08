package harvey;

import harvey.HarveyPlugin;

import java.util.function.Function;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

import org.json.simple.JSONObject;
import org.json.simple.JSONArray;
import org.json.simple.parser.ParseException;
import org.json.simple.parser.JSONParser;

public class HarveyCmds {

	public HarveyPlugin plugin;
	public Map<String, Function<Map<String, String>, String>> commands;

	public HarveyCmds(HarveyPlugin _plugin) {
		plugin = _plugin;
		commands = new HashMap<String, Function<Map<String, String>, String>>();
		commands.put("echo", this::echo);
		commands.put("jsoncmd", this::jsonCmd);
	}

	public String echo(Map<String, String> input) {
		String output = "ECHO: ";
		int index = 0;
		for (var o : input.entrySet()) {
			output = output + o.getKey() + ":" + o.getValue();
			if (index < input.size() - 1) {
				output = output + " ";
			}
			index++;
		}
		return output;
	}

	public String jsonCmd(Map<String, String> input) {
		JSONParser jp = new JSONParser();
		JSONObject jo;
		String ret;
		Function<Map<String, String>, String> func = null;
		String json = input.get("json");

		if (json == null) {
			return "error: no json provided";
		}

		try {
			jo = (JSONObject)jp.parse(input.get("json"));
			if (jo == null) {
				return "error: bad parse";
			}
			if (jo.containsKey("cmd")) {
				func = commands.get(jo.get("cmd"));
			} else {
				return "error: no command provided";
			}
			if (func == null) {
				return "error: command does not exist";
			}
			
		} catch (ParseException pe) {
			return pe.toString();
		} catch (Exception e) {
			return e.toString();
		}

		Map<String, String> m = new HashMap<String, String>();
		for (Object k : jo.keySet()) {
			try {
				if (!((String)k).equals("cmd")) {
					m.put((String)k, jo.get(k).toString());
				}
			} catch (Exception e) {
				return "error: bad json value";
			}
		}

		return func.apply(m);
	}

	public String doCommand(String line) {
		String[] parts = line.split(" ");

		if (parts.length < 1) {
			return "error: no command provided";
		}

		if (parts[0].equals("jsoncmd")) {
			Map<String, String> jsonInput = new HashMap<String, String>();
			jsonInput.put("json", line.substring(parts[0].length() + 1));

			return jsonCmd(jsonInput);
		}

		Function<Map<String, String>, String> func = commands.get(parts[0]);
		if (func == null) {
			return "error: command does not exist";
		}
		
		line = line.substring(parts[0].length() + 1);
		parts = line.split(" ");

		Map<String, String> filteredParts = new HashMap<String, String>();
		for (String s : parts) {
			String[] part_split = s.split("=");

			if (part_split.length > 1) {
				filteredParts.put(part_split[0], part_split[1]);
			} else {
				filteredParts.put(part_split[0], "");
			}
		}

		return func.apply(filteredParts);
	}
}

