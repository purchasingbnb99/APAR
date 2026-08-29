const admin = require("firebase-admin");

function getAdminApp() {
  if (admin.apps.length) return admin.app();

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  let privateKey = process.env.FIREBASE_PRIVATE_KEY;

  if (!projectId || !clientEmail || !privateKey) {
    throw new Error("Server Firebase belum dikonfigurasi. Isi FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, dan FIREBASE_PRIVATE_KEY di environment Vercel.");
  }

  privateKey = privateKey.replace(/\\n/g, "\n");

  return admin.initializeApp({
    credential: admin.credential.cert({
      projectId,
      clientEmail,
      privateKey
    })
  });
}

function json(res, status, body) {
  res.status(status).json(body);
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, {ok:false, message:"Method tidak diizinkan."});
  }

  try {
    const app = getAdminApp();
    const db = app.firestore();
    const auth = app.auth();

    const authHeader = String(req.headers.authorization || "");
    if (!authHeader.startsWith("Bearer ")) {
      return json(res, 401, {ok:false, message:"Token login Admin tidak ditemukan."});
    }

    const idToken = authHeader.slice(7).trim();
    if (!idToken) {
      return json(res, 401, {ok:false, message:"Token login Admin kosong."});
    }

    const decoded = await auth.verifyIdToken(idToken);
    const callerUid = decoded.uid;

    const callerSnap = await db.collection("users").doc(callerUid).get();
    if (!callerSnap.exists) {
      return json(res, 403, {ok:false, message:"Profil Admin tidak ditemukan."});
    }

    const caller = callerSnap.data() || {};
    if (String(caller.role || "").toLowerCase() !== "admin" ||
        String(caller.status || "").toLowerCase() !== "active") {
      return json(res, 403, {ok:false, message:"Hanya Admin aktif yang boleh mengubah password user."});
    }

    const body = req.body || {};
    const uid = String(body.uid || "").trim();
    const password = String(body.password || "");

    if (!uid) {
      return json(res, 400, {ok:false, message:"UID user wajib diisi."});
    }

    if (uid === callerUid) {
      return json(res, 400, {ok:false, message:"Gunakan mekanisme akun sendiri untuk mengubah password Admin yang sedang login."});
    }

    if (password.length < 6 || password.length > 128) {
      return json(res, 400, {ok:false, message:"Password harus 6 sampai 128 karakter."});
    }

    // Pastikan target memang mempunyai profil aplikasi.
    const targetSnap = await db.collection("users").doc(uid).get();
    if (!targetSnap.exists) {
      return json(res, 404, {ok:false, message:"Profil user tidak ditemukan di Firestore."});
    }

    const target = targetSnap.data() || {};
    if (!["admin","inspector"].includes(String(target.role || "").toLowerCase())) {
      return json(res, 400, {ok:false, message:"Role user tidak valid."});
    }

    await auth.updateUser(uid, {password});

    await db.collection("users").doc(uid).set({
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, {merge:true});

    return json(res, 200, {
      ok:true,
      message:"Password user berhasil diubah.",
      uid
    });
  } catch (err) {
    console.error("admin-user-password:", err);
    const code = String(err && err.code || "");

    if (code === "auth/id-token-expired" || code === "auth/argument-error") {
      return json(res, 401, {ok:false, message:"Sesi Admin tidak valid. Silakan login ulang."});
    }
    if (code === "auth/user-not-found") {
      return json(res, 404, {ok:false, message:"Akun Firebase Authentication user tidak ditemukan."});
    }

    return json(res, 500, {ok:false, message:err.message || "Server gagal mengubah password."});
  }
};
