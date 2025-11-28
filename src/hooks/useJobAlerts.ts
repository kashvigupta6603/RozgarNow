import { useState, useEffect, useRef } from "react";

const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://localhost:4000";

export function useJobAlerts() {
  const [newJobs, setNewJobs] = useState<any[]>([]);
  const lastCount = useRef(0);

  async function checkJobs() {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;

      const url = `${API_BASE_URL}/api/jobs/matching`;
      console.log("🔔 calling job alerts:", url); // debug ke liye

      const res = await fetch(url, {
        credentials: "include",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!res.ok) {
        console.error("Job alert fetch failed:", res.status);
        return;
      }

      const data = await res.json();

      const jobs = data.jobs || [];
      const count = jobs.length;

      // Sirf tab notify karo jab naye jobs aaye
      if (count > lastCount.current) {
        const difference = count - lastCount.current;
        setNewJobs(jobs.slice(0, difference));
      }

      lastCount.current = count;
    } catch (err) {
      console.log("Job alert error:", err);
    }
  }

  useEffect(() => {
    checkJobs(); // First load
    const interval = setInterval(checkJobs, 30000); // har 30s me check
    return () => clearInterval(interval);
  }, []);

  return newJobs;
}
