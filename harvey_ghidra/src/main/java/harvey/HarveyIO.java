package harvey;

import harvey.HarveyPlugin;

import java.awt.BorderLayout;
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

public class HarveyIO implements ActionListener
{
	public JPanel panel;
	public JTextField textCmd;
	public JTextArea textArea;
	public HarveyPlugin plugin;
	public HarveyCmds cmds;

	public HarveyIO(HarveyPlugin _plugin, HarveyCmds _cmds) {
		plugin = _plugin;
		cmds = _cmds;

		buildGui();
	}

	public void buildGui() {
		textCmd = new JTextField(20);
		textCmd.setEditable(true);
		textCmd.addActionListener(this);

		textArea = new JTextArea(5, 25);
		textArea.setEditable(false);

		panel = new JPanel(new BorderLayout());
		panel.add(new JScrollPane(textArea), BorderLayout.PAGE_START);
		panel.add(textCmd, BorderLayout.PAGE_END);
	}

	public void actionPerformed(ActionEvent evt) {
		String text = textCmd.getText();
		String output = cmds.doCommand(text);
		textArea.append("\n" + output);
		textCmd.setText("");

		//Make sure the new text is visible, even if there
		//was a selection in the text area.
		textArea.setCaretPosition(textArea.getDocument().getLength());
	}

	public JPanel getPanel() {
		return panel;
	}
}
