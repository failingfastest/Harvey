
package harvey.tests;

import harvey.HarveyIO;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class HarveyIOTests {

	public HarveyIOTests() {
	}

	@Test
	public void testAddText() {
		HarveyIO h = new HarveyIO(null);

		h.textCmd.setText("one");
		h.actionPerformed(null);

		assertEquals("\none", h.textArea.getText());
		assertEquals("", h.textCmd.getText());

		h.textCmd.setText("two");
		h.actionPerformed(null);

		assertEquals("\none\ntwo", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}
}
