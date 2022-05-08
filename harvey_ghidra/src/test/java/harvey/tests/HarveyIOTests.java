
package harvey.tests;

import harvey.HarveyIO;
import harvey.HarveyCmds;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class HarveyIOTests {

	public HarveyIOTests() {
	}

	@Test
	public void testEcho() {
		HarveyCmds c = new HarveyCmds(null);
		HarveyIO h = new HarveyIO(null, c);

		h.textCmd.setText("echo one");
		h.actionPerformed(null);

		assertEquals("\nECHO: one:", h.textArea.getText());
		assertEquals("", h.textCmd.getText());

		h.textCmd.setText("echo two=something");
		h.actionPerformed(null);

		assertEquals("\nECHO: one:\nECHO: two:something", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}

	@Test
	public void testBadCommand() {
		HarveyCmds c = new HarveyCmds(null);
		HarveyIO h = new HarveyIO(null, c);

		h.textCmd.setText("not a command");
		h.actionPerformed(null);

		assertEquals("\nerror: command does not exist", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}

	@Test
	public void testCommandNotProvided() {
		HarveyCmds c = new HarveyCmds(null);
		HarveyIO h = new HarveyIO(null, c);

		h.textCmd.setText("jsoncmd {\"not_cmd\": \"no_command\"}");
		h.actionPerformed(null);

		assertEquals("\nerror: no command provided", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}

	@Test
	public void testEchoJson() {
		HarveyCmds c = new HarveyCmds(null);
		HarveyIO h = new HarveyIO(null, c);

		h.textCmd.setText("jsoncmd {\"cmd\": \"echo\", \"arg1\": 1}");
		h.actionPerformed(null);

		assertEquals("\nECHO: arg1:1", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}

}
