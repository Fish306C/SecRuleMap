const bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken");
const user = require("./../../model/User");
const ScanResult = require("../../model/ScanResult");
// lưu ý payload có thể là algorithm (default: HS256) hoặc expiresInMinutes
module.exports.login = async (req, res) => {
  const { email, password } = req.body;
  console.log("email,password là : ", req.body);
  const response = {};

  if (!email || !password) {
    Object.assign(response, {
      status: 404,
      message: "Not Found",
    });
  } else {
    try {
      const users = await user.findOne({
        email: email,
        status: "active",
      });
      console.log("user là : ", users);
      if (!users) {
        Object.assign(response, {
          status: 404,
          message: "Not Found",
        });
      } else {
        const result = bcrypt.compareSync(password, users.password);
        console.log("result là : ", result);
        if (!result) {
          Object.assign(response, {
            status: 404,
            message: "Not Found",
          });
        } else {
          const accesstoken = jwt.sign(
            { userId: users.id, roleId: users.role_id },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRE } // kiểm tra lại tên biến env
          );

          const refresh_token = jwt.sign(
            { random: new Date().getTime() + Math.random() },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_REFRESH_EXPIRE } // kiểm tra lại tên biến env
          );

          await user.updateOne(
            { _id: users._id },
            { refresh_token: refresh_token }
          );

          Object.assign(response, {
            status: 200,
            message: "Success",
            access_Token: accesstoken,
            refresh_token: refresh_token,
          });
        }
      }
    } catch (e) {
      console.log("lỗi trong chương trình trên là : ", e);
      Object.assign(response, {
        status: 400,
        message: "Bad request",
      });
    }
  }

  res.status(response.status).json({ response });
};

module.exports.register = async (req, res) => {
  try {
    var { fullname, email, password, phone, role_id } = req.body;
    const existingUser = await user.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }
    password = bcrypt.hashSync(password, 10);
    const newUser = new user({
      fullname,
      email,
      password,
      phone,
      role_id: role_id || null,
    });
    await newUser.save();
    return res.status(201).json({
      message: "User registered successfully",
      user: newUser,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
module.exports.getProfile = async (req, res) => {
  console.log("đang chạy vào profile");
  const response = {
    status: 200,
    message: "Success",
    data: res.locals.user,
  };
  res.status(response.status).json(response);
};

// const fs = require("fs").promises;
// const path = require("path");
// const { spawn, spawnSync } = require("child_process");

// module.exports.postScan = async (req, res) => {
//   try {
//     const { url } = req.body;
//     if (!url) {
//       return res.status(400).json({ ok: false, error: "Missing url in body" });
//     }

//     const moduleCwd = path.resolve(
//       __dirname,
//       "..",
//       "..",
//       "..",
//       "tool_compliance",
//       "src"
//     );

//     // danh sách ứng viên python
//     const candidates = [
//       process.env.PYTHON_EXECUTABLE,
//       "python",
//       "python3",
//       "py",
//       "C:\\Program Files\\Python312\\python.exe",
//       "C:\\Program Files (x86)\\Python312\\python.exe",
//     ].filter(Boolean);

//     let pythonExe = null;
//     for (const cand of candidates) {
//       try {
//         const probe = spawnSync(cand, ["--version"], { timeout: 2000 });
//         if (probe && probe.status === 0) {
//           pythonExe = cand;
//           break;
//         }
//       } catch {
//         // ignore
//       }
//     }

//     if (!pythonExe) {
//       console.error("No python executable found. Tried:", candidates);
//       return res.status(500).json({
//         ok: false,
//         error: "No python executable found on PATH or given candidates",
//       });
//     }

//     const outFile = path.join(moduleCwd, `report-${Date.now()}.json`);

//     const args = [
//       "-m",
//       "tool_compliance",
//       "--url",
//       url,
//       "--spider",
//       "--passive",
//       "--output",
//       outFile,
//       "--rules-dir",
//       path.join(moduleCwd, "rules"),
//       "--auth-type",
//       "form",
//       "--auth-login-url",
//       "/login",
//       "--auth-username",
//       "anh@gmail.com",
//       "--auth-password",
//       "123",
//       "--auth-login-username-field",
//       "email",
//       "--auth-login-password-field",
//       "password",
//       "--timeout",
//       "20",
//       "--retries",
//       "1",
//     ];

//     const env = { ...process.env, PYTHONPATH: moduleCwd };

//     console.log("Spawning:", pythonExe, args.join(" "));
//     const child = spawn(pythonExe, args, {
//       cwd: moduleCwd,
//       env,
//       windowsHide: true,
//     });

//     let stdout = "",
//       stderr = "";
//     child.stdout.on("data", (d) => (stdout += d.toString()));
//     child.stderr.on("data", (d) => (stderr += d.toString()));

//     const exitCode = await new Promise((resolve, reject) => {
//       child.on("error", (err) => reject(err));
//       child.on("close", (code) => resolve(code));
//     }).catch((err) => {
//       if (!res.headersSent) {
//         return res.status(500).json({
//           ok: false,
//           error: "Failed to spawn python",
//           message: err.message, // ✅ chỉ lấy message
//         });
//       }
//     });

//     if (exitCode === undefined) return; // đã trả response rồi

//     if (exitCode !== 0) {
//       console.warn("Python process exited:", exitCode, stderr);

//       if (
//         /No module named/.test(stderr) ||
//         /ModuleNotFoundError/.test(stderr)
//       ) {
//         const mainPy = path.join(moduleCwd, "tool_compliance", "__main__.py");
//         try {
//           const child2 = spawn(pythonExe, [mainPy, ...args.slice(3)], {
//             cwd: moduleCwd,
//             env,
//             windowsHide: true,
//           });
//           let out2 = "",
//             err2 = "";
//           child2.stdout.on("data", (d) => (out2 += d.toString()));
//           child2.stderr.on("data", (d) => (err2 += d.toString()));
//           const code2 = await new Promise((resolve) =>
//             child2.on("close", resolve)
//           );
//           if (code2 !== 0) {
//             return res.status(500).json({
//               ok: false,
//               error: "Python CLI failed (fallback)",
//               code: code2,
//               stdout: out2,
//               stderr: err2,
//             });
//           }
//         } catch (e) {
//           return res.status(500).json({
//             ok: false,
//             error: "Fallback to __main__.py failed",
//             message: e.message, // ✅ chỉ trả message
//             stdout,
//             stderr,
//           });
//         }
//       } else {
//         return res.status(500).json({
//           ok: false,
//           error: "Python CLI exited with non-zero code",
//           code: exitCode,
//           stdout,
//           stderr,
//         });
//       }
//     }

//     // thành công -> đọc file output
//     try {
//       const content = await fs.readFile(outFile, "utf8");
//       try {
//         // await fs.unlink(outFile);
//       } catch {}
//       const report = JSON.parse(content);
//       return res.status(200).json({ ok: true, report, stdout, stderr });
//     } catch (err) {
//       console.error("Cannot read/parse report file:", outFile, err);
//       return res.status(500).json({
//         ok: false,
//         error: "Report file missing or invalid",
//         message: err.message, // ✅ không trả nguyên err object
//         stdout,
//         stderr,
//       });
//     }
//   } catch (ex) {
//     console.error("Unexpected controller error:", ex);
//     if (!res.headersSent) {
//       return res.status(500).json({ ok: false, error: ex.message });
//     }
//   }
// };

// const { spawn } = require("child_process");

// module.exports.postScan = async (req, res) => {
//   try {
//     const process = spawn("python", ["./pribty.py"]);

//     let result = "";

//     process.stdout.on("data", (data) => {
//       result += data.toString();
//     });

//     process.stderr.on("data", (err) => {
//       console.error("Python error:", err.toString());
//     });

//     process.on("close", (code) => {
//       console.log("chạy thành công");
//       console.log(`Python process exited with code ${code}`);
//       res.send(result.trim()); // gửi về kết quả sau khi Python chạy xong
//     });
//   } catch (error) {
//     console.log("chạy vào catch");
//     console.error(error);
//     res.status(500).send("Error running Python script");
//   }
// };

// bắt đầu 1 tiến trính mới để chạy log

const fs = require("fs").promises;
const path = require("path");
const { spawn, spawnSync } = require("child_process");
const WebSocket = require("ws");
const clients = require("../../utils/websocketStore"); // dùng chung 1 store

module.exports.startScan = async (req, res) => {
  try {
    const { url, username, password } = req.body;
    if (!url) {
      return res.status(400).json({ ok: false, error: "Missing url in body" });
    }

    console.log("url là : ", url);
    const scanId = Date.now().toString();
    const moduleCwd = path.resolve(__dirname, "../../../tool_compliance/src");

    // tìm python executable
    const candidates = [
      process.env.PYTHON_EXECUTABLE,
      "python",
      "python3",
      "py",
      "C:\\Program Files\\Python312\\python.exe",
      "C:\\Program Files (x86)\\Python312\\python.exe",
    ].filter(Boolean);

    let pythonExe = null;
    for (const cand of candidates) {
      try {
        const probe = spawnSync(cand, ["--version"], { timeout: 2000 });
        if (probe && probe.status === 0) {
          pythonExe = cand;
          break;
        }
      } catch {}
    }

    if (!pythonExe) {
      console.error("No python executable found. Tried:", candidates);
      return res.status(500).json({
        ok: false,
        error: "No python executable found on PATH or given candidates",
      });
    }

    const outFile = path.join(moduleCwd, `report-${scanId}.json`);

    const args = [
      "-m",
      "tool_compliance",
      "--url",
      url,
      "--spider",
      "--passive",
      "--output",
      outFile,
      "--rules-dir",
      path.join(moduleCwd, "rules"),
      "--auth-type",
      "form",
      "--auth-login-url",
      "/login",
      "--auth-username",
      username || "anh@gmail.com",
      "--auth-password",
      password || "123",
      "--auth-login-username-field",
      "email",
      "--auth-login-password-field",
      "password",
      "--timeout",
      "20",
      "--retries",
      "1",
    ];

    const env = { ...process.env, PYTHONPATH: moduleCwd };

    console.log("Spawning:", pythonExe, args.join(" "));

    const child = spawn(pythonExe, args, {
      cwd: moduleCwd,
      env,
      windowsHide: true,
    });

    // log exit
    child.on("exit", (code, signal) => {
      console.log("Child exited with code:", code, "signal:", signal);
    });

    // log close
    child.on("close", (code) => {
      console.log("Child closed with code:", code);
    });

    // stdout -> WebSocket
    child.stdout.on("data", (data) => {
      const client = clients.get(scanId);
      if (client?.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: "stdout", data: data.toString() }));
      }
    });

    // stderr -> WebSocket
    child.stderr.on("data", (data) => {
      const client = clients.get(scanId);
      if (client?.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: "stderr", data: data.toString() }));
      }
    });

    // error event
    child.on("error", (err) => {
      const client = clients.get(scanId);
      if (client?.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: "error", message: err.message }));
      }
    });

    // close -> đọc file + lưu DB
    child.on("close", async (code) => {
      console.log("chạy vào close");
      const client = clients.get(scanId);
      if (client?.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: "close", code }));
      }

      if (code === 0) {
        try {
          const content = await fs.readFile(outFile, "utf8");
          const report = JSON.parse(content);
          try {
            const scanerRsult = new ScanResult({
              scanId,
              start_url: report.start_url,
              summary: report.summary,
              results: report.results,
              rule_map: report.rule_map,
            });

            try {
              await scanerRsult.save();
              console.log("✅ Lưu thành công vào DB");
            } catch (err) {
              console.error("❌ Lỗi khi lưu DB:", err.message);
              console.error(err); // log chi tiết
            }
          } catch (err) {
            console.error("❌ Lỗi khi lưu:", err);
          }
          // gửi về FE
          if (client?.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: "report", data: report }));
          }

          // xóa file
          await fs.unlink(outFile);
        } catch (err) {
          if (client?.readyState === WebSocket.OPEN) {
            client.send(
              JSON.stringify({
                type: "error",
                message: "Failed to read report",
              })
            );
          }
        }
      }
    });

    // response cho FE (REST)
    res.status(200).json({ ok: true, scanId });
  } catch (ex) {
    console.error("Unexpected error:", ex);
    res.status(500).json({ ok: false, error: ex.message });
  }
};

// webscan
// controllers/wpscan.controller.js
// controllers/wpscan.controller.js
("use strict");

const axios = require("axios");

/**
 * Helper: programmatic login to WP -> return cookie string (e.g. "wordpress_logged_in=..; PHPSESSID=..")
 * Returns null on failure.
 */
async function loginAndGetCookie(baseUrl, username, password) {
  if (!baseUrl || !username || !password) return null;
  const loginUrl = new URL("/wp-login.php", baseUrl).toString();

  try {
    const resp = await axios.post(
      loginUrl,
      new URLSearchParams({
        log: username,
        pwd: password,
        "wp-submit": "Log In",
        redirect_to: `${baseUrl}/wp-admin/`,
        testcookie: "1",
      }).toString(),
      {
        maxRedirects: 0,
        // consider more statuses if your site behaves differently
        validateStatus: (s) => [200, 302, 401].includes(s),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "WPScan-Web/1.0",
        },
        timeout: 15000, // 15s for login
      }
    );

    const setCookie = resp.headers && resp.headers["set-cookie"];
    if (!setCookie || !Array.isArray(setCookie) || setCookie.length === 0) {
      return null;
    }

    // keep only "name=value" parts and join
    const cookieString = setCookie.map((c) => c.split(";")[0]).join("; ");
    return cookieString;
  } catch (err) {
    // swallow detailed error to avoid leaking sensitive info in responses
    console.error(
      "loginAndGetCookie error:",
      err && err.message ? err.message : err
    );
    return null;
  }
}

/**
 * Helper: run wpscan CLI with optional cookie & apiToken
 * Returns parsed JSON on success, or rejects with Error.
 */
function runWpscan(
  targetUrl,
  cookieString = null,
  apiToken = null,
  timeoutMs = 120000
) {
  return new Promise((resolve, reject) => {
    if (!targetUrl) return reject(new Error("targetUrl is required"));

    const args = ["--url", targetUrl, "--format", "json", "--no-banner"];
    // enumerate common things
    args.push("--enumerate", "u,ap,at,vp,vt");
    if (cookieString) {
      args.push("--cookie", cookieString);
    }
    if (apiToken) {
      args.push("--api-token", apiToken);
    }
    // set a user agent to reduce weird server behavior
    args.push("--user-agent", "WPScan-Web/1.0");

    let child;
    try {
      child = spawn("wpscan", args, { stdio: ["ignore", "pipe", "pipe"] });
    } catch (spawnErr) {
      return reject(new Error("Failed to spawn wpscan: " + String(spawnErr)));
    }

    let stdout = "";
    let stderr = "";

    if (child.stdout) {
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (d) => (stdout += d));
    }
    if (child.stderr) {
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (d) => (stderr += d));
    }

    const killer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch (e) {}
      reject(new Error("WPScan timeout"));
    }, timeoutMs);

    child.on("error", (err) => {
      clearTimeout(killer);
      reject(new Error("wpscan spawn error: " + String(err)));
    });

    child.on("close", (code) => {
      clearTimeout(killer);
      // if no stdout and non-zero exit => error
      if (!stdout || (code !== 0 && stdout.trim() === "")) {
        return reject(
          new Error(`wpscan failed (exit ${code}): ${stderr.slice(0, 1000)}`)
        );
      }

      // try parse JSON directly
      try {
        const parsed = JSON.parse(stdout);
        return resolve(parsed);
      } catch (parseErr) {
        // try to recover JSON substring
        const first = stdout.indexOf("{");
        const last = stdout.lastIndexOf("}");
        if (first !== -1 && last !== -1 && last > first) {
          const maybe = stdout.slice(first, last + 1);
          try {
            const parsed = JSON.parse(maybe);
            return resolve(parsed);
          } catch (e2) {
            // fallthrough
          }
        }
        // otherwise return raw info for debugging (caller decides)
        return resolve({ raw: stdout, stderr, exitCode: code });
      }
    });
  });
}

/**
 * Controller: getWebScan
 * Accepts req.body with either:
 *  - { url, username?, password?, apiToken? }  -> runs WPScan CLI (attempts login if username+password given)
 *  - OR { wordpress_version, plugins[], themes[], apiToken? } -> queries wpscan.com API v3
 */
module.exports.getWebScan = async (req, res) => {
  try {
    const API_TOKEN =
      process.env.WPSCAN_API_TOKEN || req.body?.apiToken || null;
    const userAgent = "MyTool/1.0 (+https://yourdomain.example)";

    const body = req.body || {};
    const {
      url,
      username,
      password,
      wordpress_version,
      plugins = [],
      themes = [],
    } = body;

    // Branch 1: CLI scan for provided URL
    if (url) {
      // validate URL
      let normalized;
      try {
        normalized = new URL(String(url));
      } catch (e) {
        return res.status(400).json({ ok: false, message: "Invalid url" });
      }

      // optionally perform login to get cookie
      let cookieString = null;
      if (username && password) {
        cookieString = await loginAndGetCookie(
          normalized.origin,
          username,
          password
        );
        if (!cookieString) {
          // decide: either continue unauthenticated or fail — here we return an error to be explicit
          return res.status(400).json({
            ok: false,
            message:
              "Login failed or cookie not obtained. If the target uses JS-based auth or 2FA, consider passing an existing session cookie instead.",
          });
        }
      }

      // run wpscan CLI
      try {
        const parsed = await runWpscan(
          normalized.href,
          cookieString,
          API_TOKEN
        );
        return res.json({ ok: true, source: "cli", data: parsed });
      } catch (err) {
        console.error(
          "WPScan CLI error:",
          err && err.message ? err.message : err
        );
        return res.status(500).json({
          ok: false,
          message: "WPScan CLI error",
          error: String(err && err.message ? err.message : err),
        });
      }
    }

    // Branch 2: API queries (must provide at least one of wordpress_version / plugins / themes)
    if (
      !wordpress_version &&
      (!Array.isArray(plugins) || plugins.length === 0) &&
      (!Array.isArray(themes) || themes.length === 0)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Provide either req.body.url (to run wpscan CLI) or at least one of: wordpress_version, plugins, themes (to query WPScan API).",
      });
    }

    if (!API_TOKEN) {
      return res.status(500).json({
        ok: false,
        message:
          "WPScan API token not configured. Set process.env.WPSCAN_API_TOKEN or pass apiToken in request body.",
      });
    }

    const headers = {
      Authorization: `Token token=${API_TOKEN}`,
      "User-Agent": userAgent,
      Accept: "application/json",
    };
    const base = "https://wpscan.com/api/v3";
    const requests = [];
    const meta = { wordpress: null, plugins: {}, themes: {} };

    if (wordpress_version) {
      const path = `${base}/wordpresses/${encodeURIComponent(
        String(wordpress_version)
      )}`;
      requests.push(
        axios
          .get(path, { headers })
          .then((r) => ({
            kind: "wordpress",
            key: wordpress_version,
            ok: true,
            data: r.data,
          }))
          .catch((err) => ({
            kind: "wordpress",
            key: wordpress_version,
            ok: false,
            error: serializeAxiosErr(err),
          }))
      );
    }

    if (Array.isArray(plugins)) {
      for (const p of plugins) {
        const slug = String(p).trim();
        if (!slug) continue;
        const path = `${base}/plugins/${encodeURIComponent(slug)}`;
        requests.push(
          axios
            .get(path, { headers })
            .then((r) => ({
              kind: "plugin",
              key: slug,
              ok: true,
              data: r.data,
            }))
            .catch((err) => ({
              kind: "plugin",
              key: slug,
              ok: false,
              error: serializeAxiosErr(err),
            }))
        );
      }
    }

    if (Array.isArray(themes)) {
      for (const t of themes) {
        const slug = String(t).trim();
        if (!slug) continue;
        const path = `${base}/themes/${encodeURIComponent(slug)}`;
        requests.push(
          axios
            .get(path, { headers })
            .then((r) => ({ kind: "theme", key: slug, ok: true, data: r.data }))
            .catch((err) => ({
              kind: "theme",
              key: slug,
              ok: false,
              error: serializeAxiosErr(err),
            }))
        );
      }
    }

    const settled = await Promise.all(requests);
    for (const item of settled) {
      if (!item) continue;
      if (item.kind === "wordpress") {
        meta.wordpress = item.ok ? { data: item.data } : { error: item.error };
      } else if (item.kind === "plugin") {
        meta.plugins[item.key] = item.ok
          ? { data: item.data }
          : { error: item.error };
      } else if (item.kind === "theme") {
        meta.themes[item.key] = item.ok
          ? { data: item.data }
          : { error: item.error };
      }
    }

    return res.json({ ok: true, source: "api", results: meta });
  } catch (err) {
    console.error(
      "getWebScan controller error:",
      err && err.stack ? err.stack : err
    );
    return res
      .status(500)
      .json({ ok: false, message: "Internal error", error: String(err) });
  }
}; // end getWebScan

/* ----------------- helpers ----------------- */
function serializeAxiosErr(err) {
  if (!err) return { message: "unknown error" };
  if (err.response) {
    return {
      status: err.response.status,
      statusText: err.response.statusText,
      body: err.response.data,
    };
  }
  return { message: err.message || String(err) };
}
