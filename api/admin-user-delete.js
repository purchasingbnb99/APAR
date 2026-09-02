const admin = require("firebase-admin");

function getAdminApp() {
  if (admin.apps.length) return admin.app();

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  let privateKey = process.env.FIREBASE_PRIVATE_KEY;

  if (!projectId || !clientEmail || !privateKey) {
    throw new Error(
      "Server Firebase belum dikonfigurasi. Isi FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, dan FIREBASE_PRIVATE_KEY di environment Vercel."
    );
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
  return res.status(status).json(body);
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, { ok:false, message:"Method tidak diizinkan." });
  }

  try {
    const app = getAdminApp();
    const auth = app.auth();
    const db = app.firestore();

    const authHeader = String(req.headers.authorization || "");
    if (!authHeader.startsWith("Bearer ")) {
      return json(res, 401, { ok:false, message:"Token login Admin tidak ditemukan." });
    }

    const idToken = authHeader.slice(7).trim();
    if (!idToken) {
      return json(res, 401, { ok:false, message:"Token login Admin kosong." });
    }

    const decoded = await auth.verifyIdToken(idToken);
    const callerUid = decoded.uid;

    const callerSnap = await db.collection("users").doc(callerUid).get();
    if (!callerSnap.exists) {
      return json(res, 403, { ok:false, message:"Profil Admin tidak ditemukan." });
    }

    const caller = callerSnap.data() || {};
    if (
      String(caller.role || "").toLowerCase() !== "admin" ||
      String(caller.status || "").toLowerCase() !== "active"
    ) {
      return json(res, 403, { ok:false, message:"Hanya Admin aktif yang boleh menghapus user." });
    }

    const body = req.body || {};
    const targetUid = String(body.uid || "").trim();
    if (!targetUid) {
      return json(res, 400, { ok:false, message:"UID user wajib diisi." });
    }

    if (targetUid === callerUid) {
      return json(res, 400, { ok:false, message:"Admin yang sedang login tidak boleh menghapus dirinya sendiri." });
    }

    const targetRef = db.collection("users").doc(targetUid);
    const targetSnap = await targetRef.get();

    if (!targetSnap.exists) {
      return json(res, 404, { ok:false, message:"Profil user tidak ditemukan di Firestore." });
    }

    const target = targetSnap.data() || {};
    const targetRole = String(target.role || "").toLowerCase();
    const targetStatus = String(target.status || "").toLowerCase();

    if (!["admin","inspector"].includes(targetRole)) {
      return json(res, 400, { ok:false, message:"Role target tidak valid." });
    }

    // Safety: do not allow the project to end with zero active Admins.
    if (targetRole === "admin" && targetStatus === "active") {
      // Read the small users master list directly instead of using a composite
      // Firestore query, so this endpoint does not require an extra index.
      const allUsersSnap = await db.collection("users").get();
      const activeAdminCount = allUsersSnap.docs.filter(docSnap=>{
        const u=docSnap.data()||{};
        return String(u.role||"").toLowerCase()==="admin"
          && String(u.status||"").toLowerCase()==="active";
      }).length;

      if (activeAdminCount <= 1) {
        return json(res, 400, {
          ok:false,
          message:"User tersebut adalah Admin aktif terakhir. Buat/aktifkan Admin lain sebelum menghapus akun ini."
        });
      }
    }

    // Count history only for confirmation/audit information. Histori is NOT deleted.
    const historySnap = await db.collection("inspections")
      .where("inspectorId", "==", targetUid)
      .get();

    const inspectionCount = historySnap.size;
    const targetLabel = String(
      target.name || target.email || target.phone || target.loginId || targetUid
    );

    // Delete Authentication credential first.
    // If Auth deletion fails, Firestore profile remains intact and can be retried.
    await auth.deleteUser(targetUid);

    // Then delete only the user profile. Inspection history is intentionally preserved.
    await targetRef.delete();

    // Immutable audit record of the deletion.
    await db.collection("activity_logs").add({
      type: "user_deleted",
      action: "DELETE_USER",
      userId: callerUid,
      targetUserId: targetUid,
      targetName: targetLabel,
      targetRole,
      preservedInspectionHistoryCount: inspectionCount,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return json(res, 200, {
      ok:true,
      message:"User berhasil dihapus. Histori pemeriksaan tetap dipertahankan.",
      uid: targetUid,
      preservedInspectionHistoryCount: inspectionCount
    });
  } catch (err) {
    console.error("admin-user-delete:", err);
    const code = String(err && err.code || "");

    if (code === "auth/id-token-expired" || code === "auth/argument-error") {
      return json(res, 401, { ok:false, message:"Sesi Admin tidak valid. Silakan login ulang." });
    }
    if (code === "auth/user-not-found") {
      return json(res, 404, { ok:false, message:"Akun Firebase Authentication user tidak ditemukan. Profile Firestore tidak dihapus otomatis." });
    }
    if (code === "permission-denied" || code === "7") {
      return json(res, 403, { ok:false, message:"Server tidak memiliki izin Firestore untuk menyelesaikan penghapusan user." });
    }

    return json(res, 500, {
      ok:false,
      message: err.message || "Server gagal menghapus user."
    });
  }
};
