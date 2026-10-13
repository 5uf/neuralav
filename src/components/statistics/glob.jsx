import { onMount } from "solid-js";
import { Chart, Title, Tooltip, Legend, Colors } from "chart.js";
import { Pie } from "solid-chartjs";
import { useNavigate } from "@solidjs/router";
import "./glob.css";

export default function Glob() {
  const navigate = useNavigate();

  onMount(() => {  
    Chart.register(Title, Tooltip, Legend, Colors);
  });

  const chartData = {
    label: "Global Statistics",
    labels: ["Malicious", "Undetected", "Unknown"],
    datasets: [
      {
        label: "Global Statistics",
        data: [19, 49, 4],
        backgroundColor: [
          "rgba(255, 99, 132, 0.2)",
          "rgba(255, 206, 86, 0.2)",
          "rgba(54, 162, 235, 0.2)",
        ],
        borderColor: [
          "rgba(255, 99, 132, 1)",
          "rgba(255, 206, 86, 1)",
          "rgba(54, 162, 235, 1)",
        ],
        borderWidth: 1,
      },
    ],
  };
  const chartOptions = {
    title: {
      display: true,
      text: "Global Statistics",
    },
    plugins: {
      legend: {
        display: true,
        position: "bottom",
      },
    },
  };

  return (
    <div class="glob-container">
      <h1>Statistics of AV Detection on BlackMamba</h1>
      
      <div class="chart-container">
      <Pie data={chartData} options={chartOptions} />
      <p>
      As of 1st January 2024
      </p>
      </div>
      <div class="chart-btn">
      <button onClick={() => navigate("/avstats")}>Show list of AVs</button>
      <button onClick={() => navigate("/comparison")}>Model Comparison</button>
      </div>
      
    </div>
  );
}
