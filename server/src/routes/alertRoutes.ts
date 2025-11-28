// src/routes/notificationRoutes.ts (or your actual path)
import { Router, Request, Response } from "express";
import nodemailer from "nodemailer";
import prisma from "../prisma";
import authMiddleware from "../middleware/authMiddleware";
import {
  sendAlertsToAllUsers,
  findMatchedJobsForPref,
} from "../controllers/notificationController";
import { sendMail } from "../services/emailService";

const router = Router();

// If you extended Request in authMiddleware via declare module,
// this is just for local typing clarity:
interface AuthedRequest extends Request {
  user?: {
    id: number;
  };
}

/* --------------------------------------------------
   1️⃣ SUBSCRIBE ROUTE
-------------------------------------------------- */
router.post("/subscribe", async (req: Request, res: Response) => {
  const { email, categories, qualifications, locations } = req.body;

  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Job Alerts Subscription is Active! 🎉",
      text: `Thanks for subscribing!\n\nCategories: ${categories?.join(", ")}`,
    });

    return res.json({ success: true, message: "Email sent" });
  } catch (err) {
    console.log("EMAIL ERROR:", err);
    return res.status(500).json({ success: false, message: "Email failed" });
  }
});

/* --------------------------------------------------
   2️⃣ TRIGGER FOR ALL USERS (Admin only)
-------------------------------------------------- */
router.get("/trigger-all", async (req: Request, res: Response) => {
  try {
    return await sendAlertsToAllUsers(null, res);
  } catch (err) {
    console.log("Trigger ALL error:", err);
    return res.status(500).json({ success: false });
  }
});

/* --------------------------------------------------
   3️⃣ TRIGGER FOR CURRENT LOGGED-IN USER ONLY 
   (Solve your problem: "har user ko mat bhejo")
-------------------------------------------------- */
router.get(
  "/trigger-one",
  authMiddleware,
  async (req: AuthedRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: { preferences: true },
      });

      if (!user || !user.preferences.length) {
        return res.json({
          success: false,
          message: "No preferences found",
        });
      }

      const pref = user.preferences[0];

      // use imported matcher directly (no require)
      const matchedJobs = await findMatchedJobsForPref(pref);

      if (!matchedJobs.length) {
        return res.json({
          success: true,
          message: "No matched jobs for you right now",
          sent: false,
        });
      }

      const top = matchedJobs.slice(0, 5);

      await sendMail(
        user.email,
        "Your matched jobs — RozgarNow",
        `<h2>Here are your matched jobs</h2>
         <ul>
           ${top.map((j: any) => `<li>${j.title}</li>`).join("")}
         </ul>`
      );

      return res.json({ success: true, sent: true });
    } catch (err) {
      console.log("Trigger ONE error:", err);
      return res.status(500).json({ success: false });
    }
  }
);

export default router;
