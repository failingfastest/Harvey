// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
package harvey;

import harvey.HarveyPlugin;
import harvey.HarveySocket;

import java.awt.BorderLayout;
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

import java.io.IOException;
import java.lang.Thread;

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
	public HarveySocket harveySocket;
	public Thread harveySocketThread;

	public HarveyIO(HarveyPlugin _plugin, HarveyCmds _cmds) {
		plugin = _plugin;
		cmds = _cmds;

		buildGui();
	}

	public void start() {
		try {
			harveySocket = new HarveySocket(plugin, this);
			harveySocketThread = new Thread(harveySocket);
			harveySocketThread.start();
		} catch (IOException ioe) {
		}
	}

	public void buildGui() {
		textCmd = new JTextField(20);
		textCmd.setEditable(true);
		textCmd.addActionListener(this);

		textArea = new JTextArea(50, 25);
		textArea.setEditable(false);

		panel = new JPanel(new BorderLayout());
		JScrollPane scrollPane = new JScrollPane(textArea);
		panel.add(scrollPane, BorderLayout.PAGE_START);
		scrollPane.setPreferredSize(new Dimension(400, 400));
		panel.add(textCmd, BorderLayout.PAGE_END);
	}

	public void actionPerformed(ActionEvent evt) {
		String text = textCmd.getText();
		String output = cmds.doCommand(text);
		log(text);
		log(output);
		textCmd.setText("");

		//Make sure the new text is visible, even if there
		//was a selection in the text area.
		textArea.setCaretPosition(textArea.getDocument().getLength());
	}

	public void log(String line) {
		textArea.append("\n" + line);
	}

	public JPanel getPanel() {
		return panel;
	}
}
