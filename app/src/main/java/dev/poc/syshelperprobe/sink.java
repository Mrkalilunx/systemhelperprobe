package dev.poc.syshelperprobe;

import android.os.Handler;
import android.os.Looper;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 环回口上的最小 HTTP 接收器，充当「第三方服务器」
 *
 * Android 的 127.0.0.1 是全网设备共享的，所以把目标应用的 serverAddress 指到
 * http://127.0.0.1:端口 之后，目标进程自己就会把报文投递到这个 socket
 * 不需要任何 VPN、iptables 或 root 配合，也不需要把数据真发到公网
 *
 * 收下来的 body 是 AES/ECB 密文，密钥为 MD5(明文)，第三方无法反解
 * 因此这条链路的真实危害是「数据改道 + 可留存 + 可拒绝服务 + 元数据明文暴露」
 * 而不是「明文被直接读取」，登记时不要夸大
 */
public final class sink {

    public interface listener {
        void onevent(String line);
    }

    private final int port;
    private final listener cb;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss", Locale.US);

    private volatile ServerSocket server;
    private volatile boolean running;
    private Thread worker;
    private int count;

    public sink(int port, listener cb) {
        this.port = port;
        this.cb = cb;
    }

    public boolean isrunning() {
        return running;
    }

    public int getport() {
        return port;
    }

    /**
     * 只绑环回口，避免把接收器暴露到 WiFi 上
     */
    public void start() {
        if (running) {
            return;
        }
        try {
            server = new ServerSocket(port, 8, InetAddress.getByName("127.0.0.1"));
            running = true;
        } catch (Exception e) {
            emit("启动失败: " + e);
            return;
        }
        emit("已监听 127.0.0.1:" + port);
        worker = new Thread(new Runnable() {
            @Override
            public void run() {
                while (running) {
                    Socket s = null;
                    try {
                        s = server.accept();
                        handle(s);
                    } catch (Exception e) {
                        if (running) {
                            emit("accept 异常: " + e);
                        }
                    } finally {
                        closesilent(s);
                    }
                }
            }
        }, "sink-accept");
        worker.setDaemon(true);
        worker.start();
    }

    public void stop() {
        running = false;
        try {
            if (server != null) {
                server.close();
            }
        } catch (Exception ignored) {
        }
        server = null;
        emit("已停止");
    }

    /**
     * 解析一条请求，只认 Content-Length，够用且不给解析器留坑
     */
    private void handle(Socket s) {
        try {
            s.setSoTimeout(8000);
            InputStream in = new BufferedInputStream(s.getInputStream());

            String reqline = readline(in);
            if (reqline == null) {
                return;
            }
            int len = 0;
            String ctype = "";
            String line;
            while ((line = readline(in)) != null && !line.isEmpty()) {
                String low = line.toLowerCase(Locale.US);
                if (low.startsWith("content-length:")) {
                    len = parseInt(line.substring(15).trim());
                } else if (low.startsWith("content-type:")) {
                    ctype = line.substring(13).trim();
                }
            }

            byte[] body = readbody(in, len);

            String[] parts = reqline.split(" ");
            String method = parts.length > 0 ? parts[0] : "?";
            String target = parts.length > 1 ? parts[1] : "?";

            count++;
            String stamp = fmt.format(new Date());
            String head = "[" + stamp + "] #" + count + " " + method + " " + target
                    + " len=" + body.length
                    + (ctype.isEmpty() ? "" : " ctype=" + ctype);

            emit(head);
            if (body.length > 0) {
                String hex = hexdump(body, 96);
                emit("  body[0..] = " + hex);
            }
            appendfile(head);
            appendfile("  body_b64 = " + base64(body));

            OutputStream out = s.getOutputStream();
            byte[] ok = ("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII);
            out.write(ok);
            out.flush();
        } catch (Exception e) {
            emit("处理请求异常: " + e);
        }
    }

    private static String readline(InputStream in) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream(128);
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                break;
            }
            if (c != '\r') {
                b.write(c);
            }
            if (b.size() > 8192) {
                break;
            }
        }
        if (c == -1 && b.size() == 0) {
            return null;
        }
        return new String(b.toByteArray(), StandardCharsets.US_ASCII);
    }

    private static byte[] readbody(InputStream in, int len) throws Exception {
        if (len <= 0) {
            return new byte[0];
        }
        if (len > 1 << 20) {
            len = 1 << 20;
        }
        byte[] buf = new byte[len];
        int off = 0;
        while (off < len) {
            int n = in.read(buf, off, len - off);
            if (n < 0) {
                break;
            }
            off += n;
        }
        if (off == len) {
            return buf;
        }
        byte[] cut = new byte[off];
        System.arraycopy(buf, 0, cut, 0, off);
        return cut;
    }

    private static int parseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (Exception e) {
            return 0;
        }
    }

    private static String hexdump(byte[] b, int max) {
        StringBuilder sb = new StringBuilder();
        int n = Math.min(b.length, max);
        for (int i = 0; i < n; i++) {
            sb.append(String.format(Locale.US, "%02x", b[i]));
        }
        if (b.length > n) {
            sb.append("...(").append(b.length).append(" B)");
        }
        return sb.toString();
    }

    private static String base64(byte[] b) {
        try {
            return android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 落盘一份，避免日志被系统刷掉后无证可查
     */
    private void appendfile(String text) {
        try {
            File f = new File(dir(), "capture.log");
            FileOutputStream fo = new FileOutputStream(f, true);
            try {
                fo.write((text + "\n").getBytes(StandardCharsets.UTF_8));
            } finally {
                fo.close();
            }
        } catch (Exception ignored) {
        }
    }

    private final java.util.ArrayList<File> dirs = new java.util.ArrayList<File>();

    public void setdir(File d) {
        if (d != null) {
            dirs.add(d);
        }
    }

    private File dir() {
        for (File d : dirs) {
            if (d != null) {
                return d;
            }
        }
        throw new IllegalStateException("未设置落盘目录");
    }

    private void emit(final String line) {
        if (cb == null) {
            return;
        }
        ui.post(new Runnable() {
            @Override
            public void run() {
                cb.onevent(line);
            }
        });
    }

    private static void closesilent(Socket s) {
        if (s == null) {
            return;
        }
        try {
            s.close();
        } catch (Exception ignored) {
        }
    }
}
