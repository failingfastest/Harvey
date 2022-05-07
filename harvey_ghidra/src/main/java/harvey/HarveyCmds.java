package harvey;

import harvey.HarveyPlugin;

import java.util.function.Function;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

public class HarveyCmds {

	public HarveyPlugin plugin;
	public Map<String, Function<List<String>, String>> commands;

	public HarveyCmds(HarveyPlugin _plugin) {
		plugin = _plugin;
		commands = new HashMap<String, Function<List<String>, String>>();
		commands.put("echo", this::echo);
	}

	public String echo(List<String> input) {
		String output = "ECHO: ";
		int index = 0;
		for (String s : input) {
			if (index > 0) {
				output = output + s;
				if (index < input.size() - 1) {
					output = output + " ";
				}
			}
			index++;
		}
		return output;
	}

	public String doCommand(String line) {
		String[] parts = line.split(" ");

		if (parts.length < 1) {
			return "error: no command provided";
		}

		Function<List<String>, String> func = commands.get(parts[0]);
		if (func == null) {
			return "error: command does not exist";
		}
		
		List<String> filteredParts = new ArrayList<String>();
		for (String s : parts) {
			if (s != " ") {
				filteredParts.add(s);
			}
		}

		return func.apply(filteredParts);
	}
}

