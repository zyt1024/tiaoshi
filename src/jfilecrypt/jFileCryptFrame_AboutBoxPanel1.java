package jfilecrypt;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.*;
import javax.swing.border.*;

public class jFileCryptFrame_AboutBoxPanel1 extends JFrame {
    private JLabel labelTitle = new JLabel();

    private JLabel labelAuthor = new JLabel();

    private JLabel labelCopyright = new JLabel();

    private JLabel labelCompany = new JLabel();

    private GridBagLayout layoutMain = new GridBagLayout();

    private Border border = BorderFactory.createEtchedBorder();

    public jFileCryptFrame_AboutBoxPanel1() {
        try {
            jbInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.setLayout( layoutMain );
        ((JPanel)this.getContentPane()).setBorder( border );
        this.setSize(new Dimension(207, 148));
        labelTitle.setText("jFileCrypt 0.1.2");
        labelAuthor.setText("jFileCrypt Developers");
        labelCopyright.setText("GNU GPL");
        labelCompany.setText("Sourceforge.net");
        this.add(labelTitle, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,GridBagConstraints
                .NONE,
                new Insets(5, 15, 0, 15),
                0, 0));
        this.add(labelAuthor, new GridBagConstraints(0, 1, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,GridBagConstraints
                .NONE,
                new Insets(0, 15, 0, 15),
                0, 0));
        this.add(labelCopyright, new GridBagConstraints(0, 2, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,GridBagConstraints
                .NONE,
                new Insets(0, 15, 0,
                        15),
                0, 0));
        this.add(labelCompany, new GridBagConstraints(0, 3, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,GridBagConstraints
                .NONE,
                new Insets(0, 15, 5, 15),
                0, 0));
    }
}
