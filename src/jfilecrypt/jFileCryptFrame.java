package jfilecrypt;

import java.awt.*;
import java.awt.event.*;

import java.io.*;

import java.security.*;

import java.util.Enumeration;
import java.util.Properties;
import java.util.Vector;

import java.util.zip.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import javax.swing.*;
import javax.swing.event.*;

//~--- classes ----------------------------------------------------------------

public class jFileCryptFrame extends JFrame {
    private static final long serialVersionUID = 1L;

    private JButton        btChoose = new JButton();
    private JProgressBar   pbCryptProgress = new JProgressBar();
    private JPasswordField pfPassword = new JPasswordField();
    private JLabel         lbAlgorithm = new JLabel();
    private JLabel         lbSource = new JLabel();
    private JTextField     tfSourceFile = new JTextField();
    private JLabel         lbPassword = new JLabel();
    private JComboBox      cmbAlgorithm = new JComboBox();
    private JComboBox      cmbCompressionLevel = new JComboBox();
    private JButton        btDecrypt = new JButton();
    private JButton        btEncrypt = new JButton();
    private JFileChooser   fchooser = new JFileChooser();
    private JCheckBox      chbUseCompression = new JCheckBox();

    private Properties prop = new Properties();
    private long read = 0;
    private int start_for_entry_path = 0;
    private String dir_for_encrypted ="";
    private long size_all_files = 0;

    //~--- constructors -------------------------------------------------------
    /**
     * This is the main-constructor. It calls the @see jbinit() method.
     */

    public jFileCryptFrame() {
        super();
        try {
            jbInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //~--- methods ------------------------------------------------------------

    private void decrypt(final File f) {
        if(f.isDirectory()) {
            File[] files = f.listFiles();
            for(int i = 0; i<files.length; i++) {
                decrypt(files[i]);
            }
        } else {
            new Thread() {
                public void run() {
                    try {
                        String kind = (String) cmbAlgorithm.getSelectedItem(); // Which algorithm?
                        int index = kind.indexOf("(");
                        kind = kind.substring(0, index);

                        Cipher c = Cipher.getInstance(kind);
                        Key k = new SecretKeySpec(
                                new String(pfPassword.getPassword()).getBytes(), kind);

                        c.init(Cipher.DECRYPT_MODE, k);

                        String filename = f.getCanonicalPath();

                        if(filename.endsWith(prop.getProperty(kind))) {
                            filename = filename.substring(
                                    0, filename.length()
                                            - prop.getProperty(kind).length());    // -suffix
                        } else {
                            displayError("Error: Wrong file chosen",
                                    "Ending of file and chosen algorithm do not match! Filename must end with: " + prop.getProperty(kind));
                            return;
                        }

                        FileInputStream fis =
                                new FileInputStream(f.getCanonicalPath());

                        FileOutputStream fos = new FileOutputStream(filename);
                        CipherInputStream cis = new CipherInputStream(fis, c);
                        byte[] buffer = new byte[0xFFFF];
                        final long size = f.length();

                        pbCryptProgress.setMaximum((int) size);

                        for (int len; (len = cis.read(buffer)) != -1;) {
                            fos.write(buffer, 0, len);
                            read += len;
                            SwingUtilities.invokeLater(new Runnable() {
                                public void run() {
                                    pbCryptProgress.setValue((int)read);
                                    pbCryptProgress.repaint();
                                }
                            });    // Set Progress
                        }

                        cis.close();
                        fos.flush();
                        fos.close();
                        fis.close();
                        pbCryptProgress.setMaximum(100);
                        pbCryptProgress.setValue(0);

                        read = 0;
                    } catch (Exception x) {
                        x.printStackTrace();
                    }
                }
            }.start();
        }
    }

    private void encrypt(final File f) {
        if(f.isDirectory()) {
            File[] files = f.listFiles();
            for(int i = 0; i<files.length; i++) {
                encrypt(files[i]);
            }
        } else {
            new Thread() {
                public void run() {
                    try {
                        String kind = (String) cmbAlgorithm.getSelectedItem(); // Which algorithm?
                        int index = kind.indexOf("(");
                        kind = kind.substring(0, index);

                        Cipher c = Cipher.getInstance(kind);
                        Key k = new SecretKeySpec(
                                new String(pfPassword.getPassword()).getBytes(), kind);

                        c.init(Cipher.ENCRYPT_MODE, k);

                        FileInputStream fis =
                                new FileInputStream(f.getCanonicalPath());
                        FileOutputStream fos =
                                new FileOutputStream(f.getCanonicalPath()
                                        + prop.getProperty(kind));
                        CipherOutputStream cos = new CipherOutputStream(fos, c);
                        final int size = (int) f.length();
                        byte[] buffer = new byte[0xFFFF];

                        pbCryptProgress.setMaximum(size);

                        for (int len; (len = fis.read(buffer)) != -1; ) {
                            cos.write(buffer, 0, len);

                            read += len;

                            SwingUtilities.invokeLater(new Runnable() {
                                public void run() {
                                    pbCryptProgress.setValue((int)read);
                                    pbCryptProgress.repaint();
                                }
                            });    // Set Progress
                        }

                        cos.flush();
                        cos.close();
                        fos.flush();
                        fos.close();
                        fis.close();
                        pbCryptProgress.setMaximum(100);
                        pbCryptProgress.setValue(0);

                        read = 0;
                    } catch (Exception x) {
                        x.printStackTrace();
                    }
                }
            }.start();
        }
    }

    /**
     * This method shows a @see javax.swing.JFileChooser and calls then
     * the method @see setFileChosen(boolean b).
     * @param e
     */

    private void btChoose_actionPerformed(ActionEvent e) {
        try {
            if (fchooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                String path = fchooser.getSelectedFile().getCanonicalPath();
                tfSourceFile.setText(path);
            }
        } catch (IOException ioex) {
        }
    }

    /**
     * This method is called by a click of btEncrypt. It calls
     * the @see zip_encrypt(final file f, ZipOutputstream zos) or @see encrypt(final File f).
     * @param e
     */

    private void btEncrypt_actionPerformed(ActionEvent e) {
        String path = tfSourceFile.getText();
        if(! path.equals("")) { // File chosen?
            File file = new File(path);
            if(file.exists()) { // Does file exist?
                if(chbUseCompression.isSelected()) {
                    String root_directory = "";
                    if(file.isFile()) {
                        root_directory = file.getParent();
                    } else{
                        root_directory = file.getPath();
                    }
                    start_for_entry_path = root_directory.length();
                    zipVectorEncrypt(new File(path));
                } else {
                    encrypt(new File(path));
                }
            } else {
                displayError("Error: file does not exist",
                        "The file you have chosen does not exist: " + path);
            }
        }
    }

    /**
     * This method is called by a click of btDecrypt. It calls
     * the @see zip_decrypt(final file f) or @see decrypt(final File f).
     * @param e
     */

    private void btDecrypt_actionPerformed(ActionEvent e) {
        String path = tfSourceFile.getText();
        if(! path.equals("")) { // File chosen?
            File file = new File(path);
            if(file.exists()) { // Does file exist?
                if(chbUseCompression.isSelected()) {
                    String fname = file.getName();
                    // check if the suffix of selected file is ".zip"
                    if(!fname.endsWith("zip")) {
                        displayError("Error: Not a ZIP-Archive",
                                "The chosen file is not a ZIP-Archive!");
                        return;
                    }
                    try {
                        if(!zip_Has_Only_One_File(file)){
                            File pf = file.getParentFile();
                            File decrypt_dir = new File(pf,fname.substring(0,fname.length()-4));
                            decrypt_dir.mkdir();
                            dir_for_encrypted = decrypt_dir.getPath();
                        }else{
                            File pf = file.getParentFile();
                            dir_for_encrypted = pf.getPath();
                        }
                        size_all_files = file.length();
                        pbCryptProgress.setMaximum((int) size_all_files);
                        zip_decrypt(new ZipInputStream(new FileInputStream(path)));
                    } catch (FileNotFoundException f) {}
                    catch(ZipException zipex){
                        displayError("Error: Not a valid ZIP-Archive",
                                "The chosen file is not a valid ZIP-Archive!");
                    }
                    catch(IOException ioex){}
                } else {
                    decrypt(new File(path));
                }
            } else {
                displayError("Error: file does not exist",
                        "The file you have chosen does not exist: " + path);
            }
        }
    }

    /**
     * This method initialises the GUI.
     * @throws Exception
     */

    private void jbInit() throws Exception {
        this.setTitle("jFileCrypt 0.1.4");
        this.setSize(new Dimension(500, 250));
        this.setResizable(true);

        // setup components

        btChoose.setText("Choose File");
        btChoose.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                btChoose_actionPerformed(e);
            }
        });

        btEncrypt.setText("Encrypt");
        btEncrypt.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                btEncrypt_actionPerformed(e);
            }
        });

        chbUseCompression.setText("Use ZIP-Compression");

        chbUseCompression.addChangeListener(new ChangeListener() {
                                                public void stateChanged(ChangeEvent e) {
                                                    chbUseCompression_stateChanged(e);
                                                }
                                            }
        );
        btDecrypt.setText("Decrypt");
        btDecrypt.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                btDecrypt_actionPerformed(e);
            }
        });

        lbSource.setText("Source:");
        lbSource.setVerticalAlignment(JLabel.CENTER);
        lbSource.setHorizontalAlignment(JLabel.RIGHT);

        lbAlgorithm.setText("Algorithm:");
        lbAlgorithm.setVerticalAlignment(JLabel.CENTER);
        lbAlgorithm.setHorizontalAlignment(JLabel.RIGHT);

        lbPassword.setText("Password:");
        lbPassword.setVerticalAlignment(JLabel.CENTER);
        lbPassword.setHorizontalAlignment(JLabel.RIGHT);

        cmbCompressionLevel.setEnabled(false);
        prop.setProperty("Blowfish", ".blowfish");
        prop.setProperty("DES", ".des");
        prop.setProperty("TripleDES", ".3des");
        prop.setProperty("AES", ".aes");
        prop.setProperty("RC4", ".rc4");

        cmbAlgorithm.addItem("Blowfish(optional length)");
        cmbAlgorithm.addItem("DES(8)");
        cmbAlgorithm.addItem("TripleDES(24)");
        cmbAlgorithm.addItem("AES(16)");
        cmbAlgorithm.addItem("RC4(optional length)");

        for(int i=0;i<10;i++){
            cmbCompressionLevel.addItem(new Integer(i));
        }
        fchooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);

        // setup boxed layouts with panels

        JPanel jpInput = new JPanel();
        JPanel jpCompression = new JPanel();
        JPanel jpCryptButtons = new JPanel();
        JPanel jpProgress = new JPanel();

        this.getContentPane().setLayout(new GridBagLayout());
        this.getContentPane().add(jpInput, new GridBagConstraints(
                0, 0, 1, 1, 1.0, 3.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(8,8,8,8), 0, 0
        ));
        this.getContentPane().add(jpCompression, new GridBagConstraints(
                0, 1, 1, 1, 1.0, 1.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(0,0,0,0), 0, 0
        ));
        this.getContentPane().add(jpCryptButtons, new GridBagConstraints(
                0, 2, 1, 1, 1.0, 1.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(8,8,0,8), 0, 0
        ));
        this.getContentPane().add(jpProgress, new GridBagConstraints(
                0, 3, 1, 1, 1.0, 1.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(8,8,8,8), 0, 0
        ));

        // add components to the panels

        jpInput.setLayout(new GridBagLayout());
        jpInput.add(lbSource, new GridBagConstraints(
                0, 0, 1, 1, 1.0, 1.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(0,0,0,8), 0, 0
        ));
        jpInput.add(tfSourceFile, new GridBagConstraints(
                1, 0, 1, 1, 3.0, 1.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(0,0,0,8), 0, 0
        ));
        jpInput.add(btChoose, new GridBagConstraints(
                2, 0, 1, 1, 1.0, 1.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(0,0,0,0), 0, 0
        ));
        jpInput.add(lbAlgorithm, new GridBagConstraints(
                0, 1, 1, 1, 1.0, 1.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(8,0,0,8), 0, 0
        ));
        jpInput.add(cmbAlgorithm, new GridBagConstraints(
                1, 1, 1, 1, 3.0, 1.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(8,0,0,8), 0, 0
        ));
        jpInput.add(lbPassword, new GridBagConstraints(
                0, 2, 1, 1, 1.0, 1.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(8,0,0,8), 0, 0
        ));
        jpInput.add(pfPassword, new GridBagConstraints(
                1, 2, 1, 1, 3.0, 1.0, GridBagConstraints.CENTER,
                GridBagConstraints.BOTH, new Insets(8,0,0,8), 0, 0
        ));

        jpCompression.setLayout(new FlowLayout());
        jpCompression.add(chbUseCompression);
        jpCompression.add(new JLabel("Compression level: "));
        jpCompression.add(cmbCompressionLevel);

        GridLayout cryptButtonsGrid = new GridLayout(1, 2);
        cryptButtonsGrid.setHgap(8);
        jpCryptButtons.setLayout(cryptButtonsGrid);
        jpCryptButtons.add(btEncrypt);
        jpCryptButtons.add(btDecrypt);

        jpProgress.setLayout(new GridLayout(1, 1));
        jpProgress.add(pbCryptProgress);
    }

    private Vector getFileList(File file){
        if(file.isDirectory()){
            Vector vec = new Vector();
            File[] list = file.listFiles();
            for(int i=0; i < list.length; i++){
                Vector v = getFileList(list[i]);
                for(int j = 0; j < v.size(); j++){
                    vec.add(v.get(j));
                }
            }
            return vec;
        } else {
            Vector vec = new Vector();
            vec.add(file);
            size_all_files += file.length();
            return vec;
        }
    }

    private void zip_decrypt(final ZipInputStream zis) {
        new Thread() {
            public void run() {
                try {
                    ZipEntry entry = zis.getNextEntry();
                    if(entry == null){
                        pbCryptProgress.setMaximum(100);
                        read = 0;
                        pbCryptProgress.setValue(0);
                        return;
                    }
                    String kind = (String) cmbAlgorithm.getSelectedItem(); // Which algorithm?
                    int index = kind.indexOf("(");

                    kind = kind.substring(0, index);

                    Cipher c = Cipher.getInstance(kind);
                    Key k = new SecretKeySpec(new String(pfPassword.getPassword()).getBytes(), kind);

                    c.init(Cipher.DECRYPT_MODE, k);

                    String filename = dir_for_encrypted+entry.getName();

                    if (filename.endsWith(prop.getProperty(kind))) {
                        filename = filename.substring(
                                0, filename.length()
                                        - prop.getProperty(kind).length());    // -suffix
                    }
                    createFiles(new File(filename));

                    FileOutputStream  fos = new FileOutputStream(filename);
                    CipherInputStream cis = new CipherInputStream(zis, c);
                    byte[]            buffer = new byte[0xFFFF];

                    for (int len; (len = cis.read(buffer)) != -1;) {
                        fos.write(buffer, 0, len);
                        read += len;
                        SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                pbCryptProgress.setValue((int)read);
                                pbCryptProgress.repaint();
                            }
                        });    // Set Progress
                    }

                    fos.flush();
                    fos.close();

                    zip_decrypt(zis);
                } catch (Exception x) {
                    x.printStackTrace();
                }
            }
        }.start();
    }

    private void zipVectorEncrypt(final File f) {
        new Thread() {
            public void run() {
                String kind = (String) cmbAlgorithm.getSelectedItem(); // Which algorithm?
                int index = kind.indexOf("(");
                Vector vec = getFileList(f);
                kind = kind.substring(0, index);
                Cipher c;
                try {
                    c = Cipher.getInstance(kind);

                    Key k = new SecretKeySpec(new String(pfPassword.getPassword()).getBytes(), kind);

                    c.init(Cipher.ENCRYPT_MODE, k);
                    String zip_file_name;
                    if(f.isFile()) {
                        zip_file_name = f.getName().substring(0, f.getName().lastIndexOf("."))+".zip";
                    } else {
                        zip_file_name = f.getName()+".zip";
                    }

                    String zip_path = f.getAbsolutePath().substring(0,f.getAbsolutePath().length()-f.getName().length())+zip_file_name;

                    ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zip_path));
                    zos.setLevel(Integer.parseInt(cmbCompressionLevel.getSelectedItem().toString()));
                    pbCryptProgress.setMaximum((int) size_all_files);

                    for(int i=0; i < vec.size(); i++) {

                        File file = (File) vec.get(i);
                        if(!file.getName().equals(".DS_Store")){

                            String entry_path = file.getAbsolutePath().substring(start_for_entry_path)+prop.getProperty(kind);

                            ZipEntry entry = new ZipEntry(entry_path);

                            zos.putNextEntry(entry);
                            FileInputStream fis = new FileInputStream(file);
                            CipherOutputStream cos = new CipherOutputStream(new MyOutputStream(zos), c);
                            //final int size = fis.available();
                            byte[] buffer = new byte[0xFFFF];

                            for (int len; (len = fis.read(buffer)) != -1; ) {
                                cos.write(buffer, 0, len);
                                read += len;
                                SwingUtilities.invokeLater(new Runnable() {
                                    public void run() {
                                        pbCryptProgress.setValue((int)read);
                                        pbCryptProgress.repaint();
                                    }
                                });    // Set Progress
                            }

                            cos.flush();
                            cos.close();
                            fis.close();

                        }

                    }
                    zos.finish();
                    zos.close();
                    pbCryptProgress.setMaximum(100);
                    read = 0;
                    pbCryptProgress.setValue((int)read);
                }
                catch(Exception x){
                    System.out.println(x);
                }
            }
        }.start();
    }

    private void chbUseCompression_stateChanged(ChangeEvent e) {
        if(chbUseCompression.isSelected()) {
            cmbCompressionLevel.setEnabled(true);
        } else {
            cmbCompressionLevel.setEnabled(false);
        }
    }

    private void createFiles(File f){
        try {
            if(!f.getParentFile().exists()){
                createParents(f.getParentFile());
                f.createNewFile();
            }

            //f.createNewFile();
        } catch (IOException e) {
            displayError("Error: Can't create file",
                    "Can't create File: " + f.getPath());
        }
    }

    private void createParents(File file) {
        if(!file.exists()){
            createParents(file.getParentFile());
            file.mkdir();
        }
    }

    private boolean zip_Has_Only_One_File(File f) throws ZipException,
            IOException {
        ZipFile zip = new ZipFile(f);
        int entries_count = 0;
        Enumeration e = zip.entries();
        for(; e.hasMoreElements() == true;){
            e.nextElement();
            entries_count++;
        }
        if(entries_count < 2){
            return true;
        }
        else{
            return false;
        }
    }

    private class MyOutputStream extends BufferedOutputStream{
        public void close() {

        }

        public MyOutputStream(OutputStream out){
            super(out);
        }
    }

    private void displayError(String title, String text) {
        JOptionPane.showMessageDialog(this, text, title, JOptionPane.ERROR_MESSAGE);
    }
}
