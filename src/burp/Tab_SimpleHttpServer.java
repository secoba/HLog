package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.net.URI;

import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.SwingConstants;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import http.SimpleHTTPServer;

import javax.swing.JRadioButton;

/**
 * Manual Http Server
 */
public class Tab_SimpleHttpServer extends JPanel {

	private static final long serialVersionUID = 8289650497566598426L;
	private static String contentType;
	private JTextField textField_rootDir;
	private JTextField textField_port;
	private JTextField textField_timeout;

	private SimpleHTTPServer simpleHTTPServer = new SimpleHTTPServer();
	private JTextField textField_thread;
	private static JTextArea output_textArea = new JTextArea();
	private static JTextArea textArea_response = new JTextArea();
	private static JRadioButton radioButton_default;
	private static JCheckBox checkBox_contentType;
	private static JTextField textField_contenttype;
	private static JComboBox<String> comboBox_contentType;
	private JLabel server_status = new JLabel("");
	private JButton button_set_port;
	private JButton button_set_timeout;
	private JButton button_set_thread;
	
	private String help = "适用环境：内网测试，如果由公网IP也能进行外网测试" + System.lineSeparator()
			+ "功能：可自定义响应类型和响应内容的HTTP服务" + System.lineSeparator()
			+ "其他：选择默认响应内容时，服务器将响应服务器目录内容；" + System.lineSeparator()
			+ "-----选择自定义响应内容时，服务器响应自定义内容" + System.lineSeparator()
			+ "-----默认响应类型来自Combobox内容，勾选后可自定义";
	
	/**
	 * Create the panel.
	 */
	public Tab_SimpleHttpServer() {
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(null, "\u670D\u52A1\u5668\u914D\u7F6E", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(null, "\u8BF7\u6C42\u65E5\u5FD7\u4FE1\u606F", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.TRAILING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING)
						.addComponent(panel, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 857, Short.MAX_VALUE)
						.addComponent(panel_1, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 857, Short.MAX_VALUE))
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(Alignment.TRAILING, groupLayout.createSequentialGroup()
					.addContainerGap()
					.addComponent(panel, GroupLayout.PREFERRED_SIZE, 426, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(panel_1, GroupLayout.DEFAULT_SIZE, 208, Short.MAX_VALUE)
					.addContainerGap())
		);
		
		JLabel label = new JLabel("服务器目录");
		
		textField_rootDir = new JTextField();
		textField_rootDir.setText(System.getProperty("user.dir"));
		textField_rootDir.setEditable(false);
		textField_rootDir.setColumns(10);
		
		JButton button = new JButton("配置服务器目录");
		button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser=new JFileChooser();
				chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				if(chooser.showOpenDialog(Tab_SimpleHttpServer.this)==JFileChooser.APPROVE_OPTION) {
					textField_rootDir.setText(chooser.getSelectedFile().toString().trim());
				} else {
					textField_rootDir.setText(System.getProperty("user.dir"));
				}
			}
		});
		
		JLabel label_1 = new JLabel("端口");
		
		textField_port = new JTextField();
		textField_port.setEditable(false);
		textField_port.setText(String.valueOf(SimpleHTTPServer.DEFAULT_PORT));
		textField_port.setHorizontalAlignment(SwingConstants.CENTER);
		textField_port.setColumns(10);
		
		button_set_port = new JButton("配置端口");
		button_set_port.setBackground(Color.RED);
		button_set_port.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (button_set_port.getText().equals("配置端口")) {					
					textField_port.setEditable(true);
					button_set_port.setText("保存端口");
					button_set_port.setBackground(Color.GREEN);
				} else {
					textField_port.setEditable(false);
					button_set_port.setText("配置端口");
					button_set_port.setBackground(Color.RED);
				}
			}
		});
		
		JLabel label_2 = new JLabel("超时");
		
		textField_timeout = new JTextField();
		textField_timeout.setEditable(false);
		textField_timeout.setHorizontalAlignment(SwingConstants.CENTER);
		textField_timeout.setText(String.valueOf(SimpleHTTPServer.DEFAULT_TIMEOUT));
		textField_timeout.setColumns(10);
		
		button_set_timeout = new JButton("配置超时");
		button_set_timeout.setBackground(Color.RED);
		button_set_timeout.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (button_set_timeout.getText().equals("配置超时")) {
					textField_timeout.setEditable(true);
					button_set_timeout.setText("保存超时");
					button_set_timeout.setBackground(Color.GREEN);
				} else {
					textField_timeout.setEditable(false);
					button_set_timeout.setText("配置超时");
					button_set_timeout.setBackground(Color.RED);
				}
			}
		});
		
		JLabel lblContenttype = new JLabel("Content-Type");
		
		comboBox_contentType = new JComboBox<>();
		comboBox_contentType.setModel(new DefaultComboBoxModel<>(new String[] {
				"text/html", 
				"text/plain", 
				"text/xml", 
				"image/gif", 
				"image/jpeg", 
				"image/png", 
				"application/xhtml+xml", 
				"application/xml", 
				"application/atom+xml", 
				"application/json", 
				"application/pdf", 
				"application/msword", 
				"application/octet-stream", 
				"application/x-www-form-urlencoded"}));
		
		textField_contenttype = new JTextField();
		textField_contenttype.setEditable(false);
		textField_contenttype.setColumns(10);
		
		checkBox_contentType = new JCheckBox("自定义");
		checkBox_contentType.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent e) {
				if (checkBox_contentType.isSelected()) {
					textField_contenttype.setEditable(true);
				} else {
					textField_contenttype.setEditable(false);
				}
			}
		});
		
		JButton button_3 = new JButton("在线查询");
		button_3.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//在线查询：https://www.iana.org/assignments/media-types/media-types.xhtml
				//启用系统默认浏览器来打开网址。  
		        try {
		        	String raw_url = "https://www.iana.org/assignments/media-types/media-types.xhtml";
		            URI uri = new URI(raw_url);
		            Desktop.getDesktop().browse(uri);
		        } catch (Exception exception) {
		        	JOptionPane.showMessageDialog(null, exception.getMessage());
		        }
			}
		});
		
		JLabel label_3 = new JLabel("自定义响应内容：");
		
		ButtonGroup respBtn = new ButtonGroup();
		
		radioButton_default = new JRadioButton("默认");
		radioButton_default.setSelected(true);
		
		JRadioButton radioButton_manual = new JRadioButton("自定义");
		
		respBtn.add(radioButton_default);
		respBtn.add(radioButton_manual);
		
		JScrollPane scrollPane_1 = new JScrollPane();
		
		JButton btnNewButton = new JButton("启动服务");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				startServ();
			}
		});
		
		JButton button_4 = new JButton("停止服务");
		button_4.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				stopServ();
			}
		});
		
		JButton button_5 = new JButton("重启服务");
		button_5.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				stopServ();
				startServ();
			}
		});
		
		JLabel label_4 = new JLabel("线程");
		
		JLabel lblmS = new JLabel("/ms");
		
		textField_thread = new JTextField();
		textField_thread.setEditable(false);
		textField_thread.setText(String.valueOf(SimpleHTTPServer.DEFAULT_MAX_THREAD));
		textField_thread.setHorizontalAlignment(SwingConstants.CENTER);
		textField_thread.setColumns(10);
		
		button_set_thread = new JButton("配置线程");
		button_set_thread.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (button_set_thread.getText().equals("配置线程")) {
					textField_thread.setEditable(true);
					button_set_thread.setText("保存线程");
					button_set_thread.setBackground(Color.GREEN);
				} else {
					textField_thread.setEditable(false);
					button_set_thread.setText("配置线程");
					button_set_thread.setBackground(Color.RED);
				}
			}
		});
		button_set_thread.setBackground(Color.RED);
		
		JButton button_7 = new JButton("清空日志");
		button_7.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				output_textArea.setText("");
			}
		});
		
		JButton button_1 = new JButton("帮助");
		button_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JOptionPane.showMessageDialog(null, help, "插件帮助信息", JOptionPane.PLAIN_MESSAGE);
			}
		});
		
		GroupLayout gl_panel = new GroupLayout(panel);
		gl_panel.setHorizontalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
						.addComponent(scrollPane_1, GroupLayout.DEFAULT_SIZE, 833, Short.MAX_VALUE)
						.addGroup(gl_panel.createSequentialGroup()
							.addGroup(gl_panel.createParallelGroup(Alignment.LEADING, false)
								.addGroup(gl_panel.createSequentialGroup()
									.addComponent(label)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(textField_rootDir)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(button, GroupLayout.PREFERRED_SIZE, 193, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED))
								.addGroup(gl_panel.createSequentialGroup()
									.addComponent(lblContenttype)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(comboBox_contentType, GroupLayout.PREFERRED_SIZE, 175, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(textField_contenttype, GroupLayout.PREFERRED_SIZE, 155, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(checkBox_contentType)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(button_3, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
								.addGroup(gl_panel.createSequentialGroup()
									.addComponent(label_1)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(textField_port, GroupLayout.PREFERRED_SIZE, 75, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(button_set_port)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(label_2)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(textField_timeout, GroupLayout.PREFERRED_SIZE, 72, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(lblmS, GroupLayout.PREFERRED_SIZE, 26, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(button_set_timeout)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(label_4)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(textField_thread, GroupLayout.PREFERRED_SIZE, 72, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(button_set_thread, GroupLayout.PREFERRED_SIZE, 96, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED)))
							.addPreferredGap(ComponentPlacement.RELATED, 72, Short.MAX_VALUE)
							.addGroup(gl_panel.createParallelGroup(Alignment.TRAILING)
								.addComponent(btnNewButton)
								.addComponent(button_4)
								.addComponent(button_5)))
						.addGroup(gl_panel.createSequentialGroup()
							.addComponent(label_3)
							.addGap(18)
							.addComponent(radioButton_default)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(radioButton_manual)
							.addGap(18)
							.addComponent(button_1)
							.addGap(18)
							.addComponent(server_status)
							.addPreferredGap(ComponentPlacement.RELATED, 354, Short.MAX_VALUE)
							.addComponent(button_7)))
					.addContainerGap())
		);
		gl_panel.setVerticalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						.addComponent(label)
						.addComponent(textField_rootDir, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(button)
						.addComponent(btnNewButton))
					.addGap(18)
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						.addComponent(label_1)
						.addComponent(textField_port, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(button_4)
						.addComponent(button_set_port)
						.addComponent(label_2)
						.addComponent(textField_timeout, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblmS)
						.addComponent(button_set_timeout)
						.addComponent(label_4)
						.addComponent(textField_thread, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(button_set_thread))
					.addGap(18)
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblContenttype)
						.addComponent(comboBox_contentType, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(textField_contenttype, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(checkBox_contentType)
						.addComponent(button_3)
						.addComponent(button_5))
					.addGap(18)
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						.addComponent(label_3)
						.addComponent(radioButton_default)
						.addComponent(radioButton_manual)
						.addComponent(button_7)
						.addComponent(button_1)
						.addComponent(server_status))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(scrollPane_1, GroupLayout.DEFAULT_SIZE, 214, Short.MAX_VALUE)
					.addContainerGap())
		);
		
		scrollPane_1.setViewportView(textArea_response);
		panel.setLayout(gl_panel);
		panel_1.setLayout(new BorderLayout(0, 0));
		
		JScrollPane scrollPane = new JScrollPane();
		panel_1.add(scrollPane, BorderLayout.CENTER);
		
		output_textArea.setEditable(false);
		scrollPane.setViewportView(output_textArea);
		setLayout(groupLayout);
	}
	
	/**
	 * TextField dispay msg
	 */
	public static void msg(String msg) {
		String tmp = output_textArea.getText();
		output_textArea.setText(tmp + System.lineSeparator() + msg);
	}
	
	/**
	 * Get Content-Type
	 */
	public static String getContentType() {
		return Tab_SimpleHttpServer.contentType;
	}
	
	/**
	 * Default radioButton of content-type
	 */
	public static JRadioButton getDefaultRadioButton() {
		return Tab_SimpleHttpServer.radioButton_default;
	}
	
	/**
	 * Get manual content-type
	 */
	public static JTextArea getTextAreaResp() {
		return Tab_SimpleHttpServer.textArea_response;
	}
	
	/**
	 * Whether manual content-type
	 */
	public static JCheckBox getContentTypeCheckbox() {
		return Tab_SimpleHttpServer.checkBox_contentType;
	}
	
	/**
	 * Content-Type value
	 */
	public static JTextField getContentTypeTextField() {
		return Tab_SimpleHttpServer.textField_contenttype;
	}
	
	/**
	 * ContentType Combobox
	 */
	public static JComboBox<String> getContentTypeCombo() {
		return Tab_SimpleHttpServer.comboBox_contentType;
	}
	
	private void startServ() {
		if (textField_port.isEditable() || textField_thread.isEditable() || textField_timeout.isEditable()) {
			JOptionPane.showMessageDialog(null, "请先保存配置", "保存配置", JOptionPane.INFORMATION_MESSAGE);
			return;
		}
		
		int port = Integer.parseInt(textField_port.getText());
		int thread = Integer.parseInt(textField_thread.getText());
		int timeout = Integer.parseInt(textField_timeout.getText());
		String rootDir = textField_rootDir.getText().trim();
		
		//启动服务
		simpleHTTPServer.setPort(port);
		simpleHTTPServer.setRootDir(new File(rootDir));
		simpleHTTPServer.setClientTimeoutInMillis(timeout);
		simpleHTTPServer.setMaxThreads(thread);
		
		new Thread(new Runnable() {
			@Override
			public void run() {
				boolean flag = simpleHTTPServer.start();
				if (flag) {
					msg("[+] HTTP Server is started.");
				} else {
					msg("[-] HTTP Server start failed.");
				}
				
				if (simpleHTTPServer.isStarted()) {
					server_status.setText("HTTP Server Started");
					server_status.setForeground(Color.GREEN);
				} else {
					server_status.setText("HTTP Server Stoped");
					server_status.setForeground(Color.RED);
				}
			}
		}).start();
	}
	
	private void stopServ() {
		boolean isStop = simpleHTTPServer.stop();
		if (isStop) {
			msg("[+] HTTP Server is stopped.");
		} else {
			msg("[-] HTTP Server stop failed.");
		}
		
		if (simpleHTTPServer.isStarted()) {
			server_status.setText("HTTP Server Started");
			server_status.setForeground(Color.GREEN);
		} else {
			server_status.setText("HTTP Server Stoped");
			server_status.setForeground(Color.RED);
		}
	}
}
