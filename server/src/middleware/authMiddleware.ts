import express from "express";
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

type TokenPayload = {
  id: number;
};

export interface AuthedRequest extends Request {
    user?: { id: number };
    params: any;
    body: any;
}


/** Extend Express Request to include user */
declare module "express-serve-static-core" {
  interface Request {
    user?: {
      id: number;
    };
  }
}

export default function authMiddleware(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as TokenPayload;
    req.user = { id: decoded.id };
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}
